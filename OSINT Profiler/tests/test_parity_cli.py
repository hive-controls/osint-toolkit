import contextlib
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import api, cli, scans
from osint_profiler.store import Store
from authz_support import authorize_case
from test_chains import Hops, maigret_report


def run_json(root, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["--root", root, *argv, "--json"])
    return code, json.loads(out.getvalue())


class BlockingHops:
    """Fake docker/pwsh boundary whose runner blocks until the scanner terminates it."""
    def __init__(self):
        self.released = threading.Event()

    def __enter__(self):
        owner = self

        class Process:
            pid = 4242
            def __init__(self, command, **kwargs): pass
            def wait(self, **kwargs):
                owner.released.wait(5)
                return 0
            def poll(self): return 0 if owner.released.is_set() else None

        self.patches = [patch("osint_profiler.scans.shutil.which", return_value="stub"),
                        patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")),
                        patch("osint_profiler.scans.subprocess.Popen", Process),
                        patch.object(scans.Scanner, "_terminate", lambda scanner, process: owner.released.set())]
        for item in self.patches: item.start()
        return self

    def __exit__(self, *exc):
        self.released.set()
        for item in self.patches: item.stop()


class ParityCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = self.directory.name
        self.store = Store(self.root)
        self.store.create_case("c", "Synthetic")
        authorize_case(self.store, "c")

    def call(self, *argv):
        return run_json(self.root, *argv)

    def finished_job(self):
        with Hops():
            plan = api.open_case("c", store=self.store).plan("maigret", "alice", top=5)
            return api.open_case("c", store=self.store).run(plan, "RUN")["job_id"]

    def imported_fingerprint(self):
        report = Path(self.root) / "report.json"
        report.write_text(json.dumps(maigret_report("alice")), encoding="utf-8")
        self.store.import_path(report, "c")
        return self.store.summary("c")["observations"][0]["fingerprint"]

    def relation_with_evidence(self):
        report = Path(self.root) / "evidence.json"
        report.write_text(json.dumps(maigret_report("bob")), encoding="utf-8")
        artifact = self.store.import_path(report, "c")["id"]
        a, b = self.store.add_entity("c", "A")["id"], self.store.add_entity("c", "B")["id"]
        relation = self.store.add_relation("c", a, b, "associated_with")["id"]
        self.store.attach_evidence("c", relation, artifact)
        return relation, self.store.summary("c")["relations"][0]["evidence"][0]["id"]


class JobCommands(ParityCase):
    def test_list_show_and_wait_on_a_finished_job(self):
        job_id = self.finished_job()
        code, envelope = self.call("job", "list", "c")
        self.assertEqual((code, [job["id"] for job in envelope["data"]]), (0, [job_id]))
        code, envelope = self.call("job", "show", "c", job_id)
        self.assertEqual((code, envelope["data"]["result"]["tool_id"]), (0, "maigret"))
        code, envelope = self.call("job", "wait", "c", job_id, "--timeout", "1")
        self.assertEqual((code, envelope["data"]["state"]), (0, "complete"))

    def test_unknown_job_and_case_are_not_found(self):
        for argv in (["job", "show", "c", "nope"], ["job", "wait", "c", "nope"], ["job", "cancel", "c", "nope"], ["job", "list", "missing"]):
            with self.subTest(argv=argv):
                code, envelope = self.call(*argv)
                self.assertEqual((code, envelope["error"]["code"]), (1, "not-found"))

    def test_missing_arguments_are_usage(self):
        for argv in (["job", "show", "c"], ["job"], ["job", "wait", "c", "x", "--timeout", "abc"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.call(*argv)[0], 2)

    def test_cancel_stops_a_running_job_started_in_this_process(self):
        with BlockingHops() as hops:
            case = api.open_case("c", store=self.store)
            started = case.run(case.plan("maigret", "alice", top=5), "RUN", background=True)
            code, envelope = self.call("job", "cancel", "c", started["job_id"])
            self.assertEqual((code, envelope["data"]["state"]), (0, "cancelling"))
            self.assertTrue(hops.released.wait(3), "cancel never reached the runner")
            self.assertEqual(case.wait_job(started["job_id"], timeout=10)["state"], "cancelled")

    def test_wait_times_out_on_a_running_job(self):
        with BlockingHops() as hops:
            case = api.open_case("c", store=self.store)
            started = case.run(case.plan("maigret", "alice", top=5), "RUN", background=True)
            code, envelope = self.call("job", "wait", "c", started["job_id"], "--timeout", "0.3")
            self.assertEqual((code, envelope["error"]["code"]), (1, "timeout"))
            hops.released.set()
            case.wait_job(started["job_id"], timeout=10)

    def test_cancel_of_a_finished_job_is_a_failure_not_a_success(self):
        code, envelope = self.call("job", "cancel", "c", self.finished_job())
        self.assertEqual((code, envelope["error"]["code"]), (1, "failed"))


class ObservationCaseUndoRelations(ParityCase):
    def test_observation_review(self):
        fingerprint = self.imported_fingerprint()
        code, envelope = self.call("observation", "review", "c", fingerprint, "--verdict", "excluded", "--reason", "noise")
        self.assertEqual((code, envelope["data"]["status"]), (0, "excluded"))
        self.assertEqual(self.store.summary("c")["observations"][0]["review_status"], "excluded")
        self.assertEqual(self.call("observation", "review", "c", "deadbeef", "--verdict", "relevant")[1]["error"]["code"], "not-found")
        self.assertEqual(self.call("observation", "review", "c", fingerprint, "--verdict", "bogus")[0], 2)

    def test_case_update(self):
        code, envelope = self.call("case", "update", "c", "--title", "Renamed", "--status", "closed")
        self.assertEqual((code, envelope["data"]["case"]["title"], envelope["data"]["case"]["status"]), (0, "Renamed", "closed"))
        self.assertEqual(self.call("case", "update", "missing", "--title", "x")[1]["error"]["code"], "not-found")
        self.assertEqual(self.call("case", "update", "c")[0], 2)
        self.assertEqual(self.call("case", "update", "c", "--status", "bogus")[0], 2)

    def test_evidence_remove(self):
        _, evidence_id = self.relation_with_evidence()
        code, envelope = self.call("evidence", "remove", "c", evidence_id)
        self.assertEqual((code, envelope["data"]), (0, {"removed": evidence_id}))
        self.assertEqual(self.store.summary("c")["relations"][0]["evidence"], [])
        self.assertEqual(self.call("evidence", "remove", "c", evidence_id)[1]["error"]["code"], "not-found")
        self.assertEqual(self.call("evidence", "remove", "c")[0], 2)

    def test_evidence_attach_form_still_works_and_a_case_named_remove_is_not_swallowed(self):
        self.assertEqual(self.call("evidence", "c", "--relation", "x")[0], 2)

    def test_undo(self):
        a, b = self.store.add_entity("c", "A")["id"], self.store.add_entity("c", "B")["id"]
        relation = self.store.add_relation("c", a, b)["id"]
        self.store.review_relation("c", relation, "rejected", "no")
        event = next(item["id"] for item in self.store.summary("c")["events"] if item["action"] == "review_relation")
        code, envelope = self.call("undo", "c", event)
        self.assertEqual((code, envelope["data"]), (0, {"undone": event}))
        self.assertEqual(self.call("undo", "c", "nope")[0], 2)
        self.assertEqual(self.call("undo", "missing", event)[1]["error"]["code"], "not-found")

    def test_relations_list(self):
        a, b = self.store.add_entity("c", "A")["id"], self.store.add_entity("c", "B")["id"]
        relation = self.store.add_relation("c", a, b)["id"]
        code, envelope = self.call("relations", "list", "c")
        self.assertEqual((code, [item["id"] for item in envelope["data"]]), (0, [relation]))
        self.assertEqual(self.call("relations", "list", "missing")[0], 1)
        self.assertEqual(self.call("relations")[0], 2)


class CatalogAndPlan(ParityCase):
    def test_catalog_list_show_validate(self):
        code, envelope = self.call("catalog", "list")
        self.assertIn("maigret", [item["id"] for item in envelope["data"]])
        code, envelope = self.call("catalog", "show", "maigret")
        self.assertEqual((code, envelope["data"]["id"]), (0, "maigret"))
        code, envelope = self.call("catalog", "validate")
        self.assertEqual((code, envelope["data"]["valid"]), (0, True))

    def test_catalog_unknown_tool_and_missing_subcommand(self):
        self.assertEqual(self.call("catalog", "show", "nope")[1]["error"]["code"], "not-found")
        self.assertEqual(self.call("catalog")[0], 2)

    def test_validate_against_a_broken_toolkit_root_is_a_config_error(self):
        with patch.dict(os.environ, {"OSINT_TOOLKIT_ROOT": self.root}):
            code, envelope = self.call("catalog", "validate")
        self.assertEqual((code, envelope["error"]["code"]), (78, "config-provider"))

    def test_plan_carries_authorization_gates_and_confirmation(self):
        code, envelope = self.call("plan", "c", "maigret", "--target", "alice", "--top", "5")
        plan = envelope["data"]
        self.assertEqual((code, plan["authorization"]["status"], plan["confirm_required"]), (0, "valid", "RUN"))
        self.assertIn("subject_authorization", plan["gates"])
        self.assertEqual(plan["tool"], "maigret")

    def test_plan_not_found_and_usage(self):
        self.assertEqual(self.call("plan", "missing", "maigret", "--target", "alice")[1]["error"]["code"], "not-found")
        self.assertEqual(self.call("plan", "c", "maigret", "--target=-bad")[0], 2)
        self.assertEqual(self.call("plan", "c", "nope", "--target", "alice")[0], 2)
        self.assertEqual(self.call("plan", "c", "maigret")[0], 2)

    def test_plan_never_runs(self):
        with Hops() as hops:
            self.call("plan", "c", "maigret", "--target", "alice")
        self.assertEqual(hops.calls, [])


if __name__ == "__main__":
    unittest.main()
