import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler.store import Store
from osint_profiler.scans import Scanner, plan_scan
from authz_support import authorize_case

class ScanLifecycle(unittest.TestCase):
    def test_case_output_and_child_status_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp); store.create_case("scan", "Synthetic only"); authorize_case(store, "scan")
            calls = []
            class Process:
                pid = 12345
                def __init__(self, command, **kwargs):
                    calls.append((command, kwargs))
                    output = Path(kwargs["env"]["SCANNER_OUTPUT"])
                    output.joinpath("results.json").write_text(json.dumps([{"username": "fixture", "site_name": "Example", "status": "Found", "url": "https://example.test/fixture"}]))
                def wait(self, **kwargs): return 0
                def poll(self): return 0
            with patch("osint_profiler.scans.shutil.which", return_value="stub"), patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), patch("osint_profiler.scans.subprocess.Popen", Process), patch.dict("os.environ", {"FORMIC_STATUS_FILE": "parent-status", "FORMIC_RUN_ID": "parent-run"}):
                result = Scanner(store).start(plan_scan(store, "scan", "scanner", "fixture"))
            self.assertEqual(store.summary("scan")["jobs"][0]["state"], "complete")
            self.assertEqual(store.summary("scan")["counts"]["observations"], 1)
            self.assertTrue(Path(result["folder"]).is_relative_to(store.root))
            self.assertNotIn("FORMIC_STATUS_FILE", calls[0][1]["env"])

    def test_cancellation_stops_container_before_partial_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp); store.create_case("cancel", "Synthetic cancellation"); authorize_case(store, "cancel")
            outputs = []
            class Process:
                pid = 12345
                waits = 0
                def __init__(self, command, **kwargs):
                    outputs.append(Path(kwargs["env"]["SCANNER_OUTPUT"]))
                def wait(self, **kwargs):
                    self.waits += 1
                    if self.waits == 1: raise KeyboardInterrupt
                    return 130
            def command(args, **kwargs):
                if args[:3] == ["docker", "compose", "down"]:
                    outputs[0].joinpath("partial.json").write_text(json.dumps([{"username": "fixture", "site_name": "Example", "status": "Found", "url": "https://example.test/fixture"}]))
                return subprocess.CompletedProcess(args, 0, "", "")
            with patch("osint_profiler.scans.shutil.which", return_value="stub"), patch("osint_profiler.scans.subprocess.run", side_effect=command), patch("osint_profiler.scans.subprocess.Popen", Process), patch.object(Scanner, "_terminate"):
                Scanner(store).start(plan_scan(store, "cancel", "scanner", "fixture"))
            data = store.summary("cancel")
            self.assertEqual(data["jobs"][0]["state"], "cancelled")
            self.assertEqual(data["counts"]["observations"], 1)

    def test_gate_refusal_exit_codes_report_a_message(self):
        expected = {75: "Network gate refused the run (no allowlisted VPN carrying internet traffic)", 78: "Network gate configuration error"}
        for exit_code, message in expected.items():
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as tmp:
                store = Store(tmp); store.create_case("gate", "Synthetic gate refusal"); authorize_case(store, "gate")
                class Process:
                    pid = 12345
                    def __init__(self, command, **kwargs): pass
                    def wait(self, **kwargs): return exit_code
                    def poll(self): return exit_code
                with patch("osint_profiler.scans.shutil.which", return_value="stub"), patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), patch("osint_profiler.scans.subprocess.Popen", Process):
                    Scanner(store).start(plan_scan(store, "gate", "scanner", "fixture"))
                job = store.summary("gate")["jobs"][0]
                self.assertEqual(job["state"], "failed")
                self.assertEqual(job["exit_code"], exit_code)
                self.assertEqual(job["message"], message)

if __name__ == "__main__": unittest.main()
