import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import scans
from osint_profiler.schemacheck import validate
from osint_profiler.scans import Scanner, plan_scan
from osint_profiler.store import Store
from osint_profiler.util import WORKSPACE
from authz_support import authorize_case

RESULT_SCHEMA = json.loads((WORKSPACE / "shared" / "catalog" / "schema" / "result.schema.json").read_text(encoding="utf-8"))

SCANNER_REPORT = [
    {"username": "fixture", "site_name": "Example", "status": "Found", "url": "https://example.test/fixture"},
    {"username": "fixture", "site_name": "Other", "status": "Not Found", "url": "https://other.test/fixture"},
    {"username": "fixture", "site_name": "Broken", "status": "Error", "url": ""},
]
MAIGRET_REPORT = {"GitHub": {"url_user": "https://github.test/fixture", "ids_usernames": {"alias_one": "username"},
                             "status": {"status": "Claimed", "username": "fixture", "site_name": "GitHub"}}}
PHONE_REPORT = {"tool": "phone-lookup", "version": "0.1.0", "queried_at": "2026-01-01T00:00:00+00:00",
                "local": {"e164": "+15555550123", "valid": True, "line_type": "mobile", "region": "US", "location": "Somewhere", "carrier_prefix": None},
                "sources": {"hudson_rock": {"ok": True, "hit": False}, "dehashed": {"ok": False}}, "skipped": {}}


class FakeRun:
    """Stands in for pwsh/docker: writes fixture output and returns a chosen exit code."""
    def __init__(self, tool, filename=None, payload=None, code=0, explode=False):
        self.tool, self.filename, self.payload, self.code, self.explode = tool, filename, payload, code, explode

    def execute(self, store, case_id, target, kind):
        owner = self
        class Process:
            pid = 4242
            def __init__(self, command, **kwargs):
                if owner.explode: raise OSError("pwsh vanished")
                if owner.filename:
                    Path(kwargs["env"][scans.TOOLS[owner.tool][2]]).joinpath(owner.filename).write_text(json.dumps(owner.payload), encoding="utf-8")
            def wait(self, **kwargs): return owner.code
            def poll(self): return owner.code
        with patch("osint_profiler.scans.shutil.which", return_value="stub"), \
             patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             patch("osint_profiler.scans.subprocess.Popen", Process):
            return Scanner(store).start(plan_scan(store, case_id, self.tool, target, kind))


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(self.directory.name)
        self.store.create_case("env", "Synthetic envelope")
        authorize_case(self.store, "env")

    def run_tool(self, *args, target="fixture", kind="username", **kwargs):
        result = FakeRun(*args, **kwargs).execute(self.store, "env", target, kind)
        path = Path(result["folder"]) / "result.json"
        self.assertTrue(path.is_file(), "result.json missing")
        envelope = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(validate(envelope, RESULT_SCHEMA), [])
        return envelope, Path(result["folder"])

    def entities(self, envelope, kind):
        return [e for e in envelope["entities"] if e["kind"] == kind]

    def test_scanner_success_envelope(self):
        envelope, folder = self.run_tool("scanner", "results.json", SCANNER_REPORT)
        self.assertEqual((envelope["tool_id"], envelope["tool_version"], envelope["catalog_version"]), ("user-scanner", "1.5.1.3", "1"))
        self.assertEqual((envelope["case_id"], envelope["exit_code"], envelope["chain"]), ("env", 0, None))
        self.assertEqual(envelope["gate"]["network"], {"code": "PASS", "mode": None})
        self.assertEqual(envelope["gate"]["authorization"]["status"], "valid")
        self.assertTrue(envelope["gate"]["authorization"]["attestation_id"])
        self.assertEqual(envelope["inputs"], [{"name": "target", "kind": "username", "value": "fixture", "provenance": "user", "from": None}])
        data = (folder / "output" / "results.json").read_bytes()
        artifact = envelope["artifacts"][0]
        self.assertEqual((artifact["path"], artifact["sha256"], artifact["bytes"], artifact["adapter"]),
                         ("output/results.json", hashlib.sha256(data).hexdigest(), len(data), "scanner"))
        accounts = self.entities(envelope, "account")
        self.assertEqual([a["value"] for a in accounts], ["https://example.test/fixture"])
        self.assertEqual(accounts[0]["attrs"], {"site": "Example", "query": "fixture", "status": "hit", "reported_status": "Found"})
        self.assertIs(accounts[0]["identity_assertion"], False)
        self.assertEqual(accounts[0]["source_artifact_sha256"], artifact["sha256"])
        query = self.entities(envelope, "username")[0]
        self.assertEqual((query["value"], query["provenance"]), ("fixture", "user"))
        self.assertEqual(query["attrs"]["counts"], {"hit": 1, "absent": 1, "error": 1})
        self.assertFalse(any("Not Found" in json.dumps(e) and e["kind"] == "account" for e in envelope["entities"]))

    def test_maigret_derives_usernames(self):
        envelope, _ = self.run_tool("maigret", "report.json", MAIGRET_REPORT)
        derived = [e for e in self.entities(envelope, "username") if e["provenance"] == "derived"]
        self.assertEqual([(e["value"], e["attrs"]["site"]) for e in derived], [("alias_one", "GitHub")])
        self.assertEqual(envelope["tool_id"], "maigret")

    def test_phone_envelope_entities(self):
        envelope, _ = self.run_tool("phone", "lookup.json", PHONE_REPORT, target="+15555550123", kind="phone")
        self.assertEqual([e["value"] for e in self.entities(envelope, "phone.e164")], ["+15555550123"])
        meta = self.entities(envelope, "phone.meta")[0]
        self.assertEqual(meta["attrs"], {"valid": True, "line_type": "mobile", "region": "US", "location": "Somewhere", "carrier_prefix": None})
        signals = {e["attrs"]["source"]: e["attrs"]["state"] for e in self.entities(envelope, "breach.signal")}
        self.assertEqual(signals, {"hudson_rock": "absent", "dehashed": "error"})
        self.assertTrue(all(e["identity_assertion"] is False for e in envelope["entities"]))
        self.assertEqual(envelope["tool_id"], "phone-lookup")

    def test_failure_paths_still_write_a_valid_envelope(self):
        expectations = {75: (75, "network_gate_refused"), 78: (78, "network_gate_configuration"),
                        77: (None, "authorization_required"), 1: (None, "tool_failed")}
        for code, (network, error_code) in expectations.items():
            with self.subTest(code=code):
                envelope, _ = self.run_tool("scanner", code=code)
                self.assertEqual(envelope["exit_code"], code)
                self.assertEqual(envelope["gate"]["network"]["code"], network)
                self.assertEqual(envelope["errors"][0]["code"], error_code)
                self.assertTrue(envelope["errors"][0]["message"])
                self.assertEqual(envelope["artifacts"], [])

    def test_runner_exception_still_writes_envelope(self):
        envelope, _ = self.run_tool("scanner", explode=True)
        self.assertEqual(envelope["exit_code"], 1)
        self.assertIn("pwsh vanished", envelope["errors"][0]["message"])

    def test_successful_run_has_no_errors_and_job_is_complete(self):
        envelope, _ = self.run_tool("scanner", "results.json", SCANNER_REPORT)
        self.assertEqual(envelope["errors"], [])
        self.assertEqual(self.store.summary("env")["jobs"][0]["state"], "complete")


if __name__ == "__main__":
    unittest.main()
