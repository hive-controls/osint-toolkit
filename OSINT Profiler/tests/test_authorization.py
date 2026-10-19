import contextlib
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from authz_support import FIXTURE_FIELDS, authorize_case, legacy_json
from osint_profiler import authorization, cli, native
from osint_profiler.authorization import REQUIRED_PHRASE, AuthorizationRequired
from osint_profiler.scans import Scanner, plan_scan
from osint_profiler.store import Store
from osint_profiler.util import database, now
from osint_profiler.web import create_server


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def event_actions(store, case_id):
    with database(store.db_path(case_id)) as con:
        return [row["action"] for row in con.execute("SELECT action FROM events ORDER BY rowid")]


def ledger_rows(store, case_id):
    with database(store.db_path(case_id)) as con:
        return [dict(row) for row in con.execute("SELECT * FROM authorizations ORDER BY rowid")]


def edit_ledger(store, case_id, column, value):
    with database(store.db_path(case_id)) as con:
        con.execute(f"UPDATE authorizations SET {column}=?", (value,))


class LedgerBehavior(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.store.create_case("c1", "Synthetic authorization case")

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_attestation_is_refused(self):
        with self.assertRaises(AuthorizationRequired) as caught:
            authorization.require_authorization(self.store, "c1", "scan")
        self.assertEqual(caught.exception.reason, "missing")
        self.assertIsInstance(caught.exception, ValueError)

    def test_recorded_attestation_passes_and_logs_check_event(self):
        record = authorize_case(self.store, "c1")
        result = authorization.require_authorization(self.store, "c1", "scan")
        self.assertEqual(result["id"], record["id"])
        actions = event_actions(self.store, "c1")
        self.assertIn("authorization_recorded", actions)
        self.assertIn("authorization_check", actions)

    def test_failed_check_is_also_logged(self):
        with self.assertRaises(AuthorizationRequired):
            authorization.require_authorization(self.store, "c1", "scan")
        self.assertIn("authorization_check", event_actions(self.store, "c1"))

    def test_expired_attestation_is_refused(self):
        authorize_case(self.store, "c1")
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
        edit_ledger(self.store, "c1", "expires_ts", past)
        with self.assertRaises(AuthorizationRequired) as caught:
            authorization.require_authorization(self.store, "c1", "scan")
        self.assertEqual(caught.exception.reason, "expired")

    def test_revoked_attestation_is_refused_and_sidecar_marks_it(self):
        authorize_case(self.store, "c1")
        authorization.revoke_authorization(self.store, "c1", "engagement ended")
        with self.assertRaises(AuthorizationRequired) as caught:
            authorization.require_authorization(self.store, "c1", "scan")
        self.assertEqual(caught.exception.reason, "revoked")
        sidecar = json.loads((self.store.case_dir("c1") / "authorization.json").read_text(encoding="utf-8"))
        self.assertTrue(sidecar["revoked"])
        self.assertIn("authorization_revoked", event_actions(self.store, "c1"))

    def test_stale_acknowledgement_hash_is_refused(self):
        authorize_case(self.store, "c1")
        edit_ledger(self.store, "c1", "ack_version_hash", "0" * 64)
        with self.assertRaises(AuthorizationRequired) as caught:
            authorization.require_authorization(self.store, "c1", "scan")
        self.assertEqual(caught.exception.reason, "stale-ack")

    def test_identifier_shaped_subject_labels_are_rejected(self):
        for label in ("+14155550123", "alice@example.test", "@alice", "4155550123"):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    authorize_case(self.store, "c1", subject_label=label)
        self.assertEqual(ledger_rows(self.store, "c1"), [])

    def test_phrase_mismatch_writes_nothing(self):
        for phrase in (REQUIRED_PHRASE.lower(), REQUIRED_PHRASE + " ", "", "I AUTHORIZE"):
            with self.subTest(phrase=phrase):
                with self.assertRaises(ValueError):
                    authorize_case(self.store, "c1", acknowledgement=phrase)
        self.assertEqual(ledger_rows(self.store, "c1"), [])
        self.assertFalse((self.store.case_dir("c1") / "authorization.json").exists())
        self.assertNotIn("authorization_recorded", event_actions(self.store, "c1"))

    def test_enum_and_note_requirements(self):
        with self.assertRaises(ValueError):
            authorize_case(self.store, "c1", purpose="curiosity")
        with self.assertRaises(ValueError):
            authorize_case(self.store, "c1", purpose="other")
        with self.assertRaises(ValueError):
            authorize_case(self.store, "c1", legal_basis="other")
        record = authorize_case(self.store, "c1", purpose="other", purpose_note="Documented reason", legal_basis="other", basis_note="Documented basis")
        self.assertEqual(record["purpose_note"], "Documented reason")

    def test_record_fields_expiry_and_hash(self):
        record = authorize_case(self.store, "c1")
        row = ledger_rows(self.store, "c1")[0]
        self.assertEqual(row["id"], record["id"])
        self.assertEqual(row["operator"], __import__("getpass").getuser())
        self.assertEqual(row["ack_version_hash"], authorization.acknowledgement_hash())
        self.assertEqual(row["ack_phrase_sha256"], __import__("hashlib").sha256(REQUIRED_PHRASE.encode("utf-8")).hexdigest())
        issued, expires = datetime.fromisoformat(row["ts"]), datetime.fromisoformat(row["expires_ts"])
        self.assertEqual(expires - issued, timedelta(days=180))

    def test_sidecar_content(self):
        record = authorize_case(self.store, "c1")
        sidecar = json.loads((self.store.case_dir("c1") / "authorization.json").read_text(encoding="utf-8"))
        self.assertEqual(sidecar, {"attestation_id": record["id"], "case_id": "c1", "ack_version_hash": authorization.acknowledgement_hash(),
                                   "expires_ts": record["expires_ts"], "revoked": False, "subject_label": "Subject A"})

    def test_old_case_database_gains_the_table(self):
        with database(self.store.db_path("c1")) as con:
            con.execute("DROP TABLE authorizations")
            con.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
        reopened = Store(self.tmp.name)
        self.assertIsNone(authorization.current_authorization(reopened, "c1"))
        with database(reopened.db_path("c1")) as con:
            self.assertEqual(dict(con.execute("SELECT key,value FROM meta"))["schema_version"], "2")
        authorize_case(reopened, "c1")
        self.assertEqual(len(ledger_rows(reopened, "c1")), 1)

    def test_plan_scan_reports_authorization_status_without_events(self):
        before = event_actions(self.store, "c1")
        plan = plan_scan(self.store, "c1", "scanner", "fixture")
        self.assertEqual(plan["authorization"]["status"], "missing")
        self.assertEqual(event_actions(self.store, "c1"), before)
        authorize_case(self.store, "c1")
        self.assertEqual(plan_scan(self.store, "c1", "scanner", "fixture")["authorization"]["status"], "valid")


class EnforcementCallSites(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.store.create_case("bound", "Synthetic native run")
        self.folder = self.store.case_dir("bound") / "sessions/session123"
        (self.folder / "requests").mkdir(parents=True)
        (self.folder / "staging").mkdir()
        self.session = self.folder / "session.json"
        native.save(self.session, {"root": str(self.store.root), "case_id": "bound", "tool": "scanner", "id": "session123", "supervisor_pid": os.getpid(), "created": now()})

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, name):
        path = self.folder / "requests" / (name + ".json")
        native.save(path, {"session_file": str(self.session), "arguments": ["-u", "fixture", "-f", "json", "-o", "/output/report.json"], "target": "fixture"})
        return path

    def test_scanner_start_requires_attestation(self):
        plan = plan_scan(self.store, "bound", "scanner", "fixture")
        with patch("osint_profiler.scans.shutil.which", return_value="stub"), patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(AuthorizationRequired):
                Scanner(self.store).start(plan)
        self.assertEqual(self.store.summary("bound")["jobs"], [])

    def test_launch_session_requires_attestation(self):
        with self.assertRaises(AuthorizationRequired):
            native.launch_session(self.store, "bound", "scanner")

    def test_chain_hop_revocation_stops_run_request(self):
        authorize_case(self.store, "bound")
        authorization.revoke_authorization(self.store, "bound", "revoked mid-session")
        with patch.object(native, "project_busy"), patch.object(native, "powershell", return_value="stub"):
            with self.assertRaises(AuthorizationRequired) as caught:
                native.run_request(self.request("one"))
        self.assertEqual(caught.exception.reason, "revoked")
        self.assertEqual(self.store.summary("bound")["jobs"], [])


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.store.create_case("c1", "Synthetic authorization case")

    def tearDown(self):
        self.tmp.cleanup()

    def authorize_flags(self, case_id="c1", phrase=REQUIRED_PHRASE):
        return ["--root", self.tmp.name, "authorize", case_id, "--subject-label", FIXTURE_FIELDS["subject_label"], "--purpose", FIXTURE_FIELDS["purpose"],
                "--legal-basis", FIXTURE_FIELDS["legal_basis"], "--jurisdiction", FIXTURE_FIELDS["jurisdiction"], "--acknowledge", phrase, "--json"]

    def test_scan_without_attestation_exits_77_with_json_shape(self):
        code, out, _ = run_cli("--root", self.tmp.name, "scan", "c1", "--tool", "scanner", "--target", "fixture", "--confirm", "RUN", "--json")
        self.assertEqual(code, 77)
        payload = legacy_json(out)
        self.assertEqual(payload["error"], "subject-authorization-required")
        self.assertEqual((payload["case_id"], payload["reason"], payload["next"]), ("c1", "missing", "osint-case authorize c1"))
        self.assertTrue(payload["message"])

    def test_scan_without_attestation_exits_77_in_text_mode(self):
        code, out, err = run_cli("--root", self.tmp.name, "scan", "c1", "--tool", "scanner", "--target", "fixture", "--confirm", "RUN")
        self.assertEqual(code, 77)
        self.assertIn("osint-case authorize c1", err)

    def test_authorize_flags_records_and_scan_passes_the_check(self):
        code, out, _ = run_cli(*self.authorize_flags())
        self.assertEqual(code, 0)
        self.assertEqual(legacy_json(out)["case_id"], "c1")
        self.assertEqual(authorization.authorization_status(self.store, "c1")["status"], "valid")

    def test_authorize_with_wrong_phrase_writes_nothing(self):
        code, _, _ = run_cli(*self.authorize_flags(phrase=REQUIRED_PHRASE.lower()))
        self.assertNotEqual(code, 0)
        self.assertEqual(ledger_rows(self.store, "c1"), [])

    def test_ack_file_matches_flags(self):
        self.store.create_case("c2", "Second synthetic case")
        run_cli(*self.authorize_flags("c1"))
        ack_file = Path(self.tmp.name) / "ack.json"
        ack_file.write_text(json.dumps({**FIXTURE_FIELDS, "acknowledge": REQUIRED_PHRASE}), encoding="utf-8")
        code, _, _ = run_cli("--root", self.tmp.name, "authorize", "c2", "--ack-file", str(ack_file), "--json")
        self.assertEqual(code, 0)
        by_flags, by_file = ledger_rows(self.store, "c1")[0], ledger_rows(self.store, "c2")[0]
        for column in ("subject_label", "purpose", "purpose_note", "legal_basis", "basis_note", "jurisdiction", "ack_version_hash", "ack_phrase_sha256", "operator"):
            self.assertEqual(by_flags[column], by_file[column], column)

    def test_show_and_revoke(self):
        run_cli(*self.authorize_flags())
        code, out, _ = run_cli("--root", self.tmp.name, "authorize", "c1", "--show", "--json")
        self.assertEqual((code, legacy_json(out)["status"]), (0, "valid"))
        code, _, _ = run_cli("--root", self.tmp.name, "authorize", "c1", "--revoke", "--reason", "done", "--json")
        self.assertEqual(code, 0)
        code, out, _ = run_cli("--root", self.tmp.name, "authorize", "c1", "--show", "--json")
        self.assertEqual(legacy_json(out)["status"], "revoked")
        code, out, _ = run_cli("--root", self.tmp.name, "scan", "c1", "--tool", "scanner", "--target", "fixture", "--confirm", "RUN", "--json")
        self.assertEqual((code, legacy_json(out)["reason"]), (77, "revoked"))

    def test_first_scan_on_a_tty_prompts_inline_once_then_prints_banner_once(self):
        from osint_profiler import authorize_cli
        calls = []
        with patch.object(authorize_cli.sys.stdin, "isatty", return_value=True), patch.object(authorize_cli, "interactive_authorize", side_effect=lambda s, c: calls.append(c) or authorize_case(s, c)):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                authorize_cli.ensure_scan_authorization(self.store, "c1")
            self.assertEqual(calls, ["c1"])
            self.assertEqual(err.getvalue().count("Authorized, lawful use only."), 1)
            authorization.require_authorization(self.store, "c1", "scan")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                authorize_cli.ensure_scan_authorization(self.store, "c1")
            self.assertEqual(calls, ["c1"])
            self.assertNotIn("Authorized, lawful use only.", err.getvalue())

    def test_authorize_prints_banner_in_text_mode(self):
        flags = [value for value in self.authorize_flags() if value != "--json"]
        code, out, err = run_cli(*flags)
        self.assertEqual(code, 0)
        self.assertIn("Authorized, lawful use only. See LEGAL-USE.md.", out + err)


class WebEditor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.store.create_case("c1", "Synthetic authorization case")
        self.server = create_server(self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with self.opener.open(self.base + "/api/session") as response:
            self.token = json.load(response)["data"]["token"]

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.tmp.cleanup()

    def post(self, action, args):
        headers = {"Content-Type": "application/json", "X-Profiler-Token": self.token, "Origin": self.base}
        request = urllib.request.Request(self.base + "/api/action", json.dumps({"action": action, "args": args}).encode(), headers)
        with self.opener.open(request) as response:
            return json.load(response)["data"]

    def test_open_scanner_surfaces_authorization_error(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post("open_scanner", {"case_id": "c1", "tool": "scanner"})
        body = json.load(caught.exception)
        caught.exception.close()
        self.assertEqual(body["error"], "subject-authorization-required")
        self.assertEqual((body["case_id"], body["reason"]), ("c1", "missing"))

    def test_start_scan_surfaces_authorization_error(self):
        plan = self.post("plan_scan", {"case_id": "c1", "tool": "scanner", "target": "fixture"})
        self.assertEqual(plan["authorization"]["status"], "missing")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post("start_scan", {"plan_id": plan["plan_id"], "confirm": "RUN"})
        body = json.load(caught.exception)
        caught.exception.close()
        self.assertEqual(body["error"], "subject-authorization-required")

    def test_authorization_text_action_exposes_phrase_and_text(self):
        data = self.post("authorization_text", {})
        self.assertEqual(data["phrase"], REQUIRED_PHRASE)
        self.assertEqual(data["text"], authorization.acknowledgement_text())

    def test_authorize_action_records_attestation(self):
        data = self.post("authorize", {"case_id": "c1", **FIXTURE_FIELDS, "acknowledgement": REQUIRED_PHRASE})
        self.assertEqual(data["case_id"], "c1")
        self.assertEqual(authorization.authorization_status(self.store, "c1")["status"], "valid")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post("authorize", {"case_id": "c1", **FIXTURE_FIELDS, "acknowledgement": "nope"})
        caught.exception.close()
        self.assertEqual(len(ledger_rows(self.store, "c1")), 1)


if __name__ == "__main__":
    unittest.main()
