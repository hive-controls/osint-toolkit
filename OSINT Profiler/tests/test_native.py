import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from osint_profiler.store import Store
from osint_profiler import native
from osint_profiler.util import now
from authz_support import authorize_case


class NativeRuns(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.store.create_case("bound", "Synthetic native run")
        self.store.create_case("other", "Unrelated synthetic case")
        authorize_case(self.store, "bound")
        self.folder = self.store.case_dir("bound") / "sessions/session123"
        (self.folder / "requests").mkdir(parents=True)
        (self.folder / "staging").mkdir()
        self.session = self.folder / "session.json"
        native.save(self.session, {"root": str(self.store.root), "case_id": "bound", "tool": "scanner", "id": "session123", "supervisor_pid": os.getpid(), "created": now()})

    def tearDown(self): self.tmp.cleanup()

    def request(self, name, arguments=None):
        request = self.folder / "requests" / (name + ".json")
        native.save(request, {"session_file": str(self.session), "arguments": arguments or ["-u", "fixture", "-f", "json", "-o", "/output/report.json"], "target": "fixture"})
        return request

    def test_per_run_imports_bound_case_and_keeps_terminal_streams(self):
        calls = []
        class Process:
            def __init__(self, argv, **kwargs):
                calls.append(kwargs)
                output = Path(kwargs["env"]["SCANNER_OUTPUT"])
                output.joinpath("report.json").write_text(json.dumps([{"username": "fixture", "site_name": "Example", "status": "Found", "url": "https://example.test/fixture"}]))
            def wait(self, **kwargs): return 0
        with patch.object(native, "project_busy"), patch.object(native, "powershell", return_value="stub"), patch.object(native.subprocess, "Popen", Process), patch.dict(os.environ, {"FORMIC_STATUS_FILE": "parent", "SCANNER_OUTPUT": "wrong"}):
            self.assertEqual(native.run_request(self.request("one")), 0)
            self.assertEqual(native.run_request(self.request("two")), 0)
        self.assertNotIn("stdin", calls[0]); self.assertNotIn("stdout", calls[0])
        self.assertNotIn("FORMIC_STATUS_FILE", calls[0]["env"])
        self.assertNotEqual(calls[0]["env"]["SCANNER_OUTPUT"], calls[1]["env"]["SCANNER_OUTPUT"])
        data = self.store.summary("bound")
        self.assertEqual(len(data["jobs"]), 2)
        self.assertTrue(all(j["state"] == "complete" for j in data["jobs"]))
        self.assertEqual(data["counts"]["observations"], 1)
        self.assertEqual(self.store.summary("other")["counts"]["observations"], 0)

    def test_bulk_input_copied_but_not_imported_and_failed_run_retained(self):
        self.folder.joinpath("staging/targets.csv").write_text("fixture\n")
        calls = []
        class Process:
            def __init__(self, argv, **kwargs):
                output = Path(kwargs["env"]["SCANNER_OUTPUT"])
                calls.append(output.joinpath("targets.csv").read_text())
                output.joinpath("partial.json").write_text(json.dumps([{"username": "fixture", "site_name": "Example", "status": "Found", "url": "https://example.test/fixture"}]))
            def wait(self, **kwargs): return 7
        with patch.object(native, "project_busy"), patch.object(native, "powershell", return_value="stub"), patch.object(native.subprocess, "Popen", Process):
            self.assertEqual(native.run_request(self.request("bulk", ["-uf", "/output/targets.csv", "-f", "json", "-o", "/output/partial.json"])), 7)
        data = self.store.summary("bound")
        self.assertEqual(calls, ["fixture\n"])
        self.assertEqual(data["jobs"][0]["state"], "failed")
        self.assertEqual(len(data["artifacts"]), 1)
        self.assertEqual(data["artifacts"][0]["name"], "partial.json")

    def test_native_runs_write_a_valid_result_envelope(self):
        from osint_profiler.schemacheck import validate
        from osint_profiler.util import WORKSPACE
        schema = json.loads((WORKSPACE / "shared/catalog/schema/result.schema.json").read_text(encoding="utf-8"))
        for exit_code in (0, 7):
            class Process:
                def __init__(self, argv, **kwargs):
                    Path(kwargs["env"]["SCANNER_OUTPUT"]).joinpath("report.json").write_text(json.dumps([{"username": "fixture", "site_name": "Example", "status": "Found", "url": "https://example.test/fixture"}]))
                def wait(self, **kwargs): return exit_code
            with self.subTest(exit_code=exit_code), patch.object(native, "project_busy"), patch.object(native, "powershell", return_value="stub"), patch.object(native.subprocess, "Popen", Process):
                native.run_request(self.request(f"env{exit_code}"))
                job = next(j for j in self.store.summary("bound")["jobs"] if j["exit_code"] == exit_code)
                envelope = json.loads(self.store.resolve_run_path("bound", job["path"]).joinpath("result.json").read_text(encoding="utf-8"))
                self.assertEqual(validate(envelope, schema), [])
                self.assertEqual((envelope["tool_id"], envelope["exit_code"], envelope["job_id"]), ("user-scanner", exit_code, job["id"]))
                self.assertEqual(envelope["inputs"][0]["kind"], "username")
                self.assertEqual(len([e for e in envelope["entities"] if e["kind"] == "account"]), 1)

    def test_failed_request_is_not_reexecuted(self):
        request = self.request("once")
        with patch.object(native, "project_busy", side_effect=ValueError("Docker unavailable")):
            with self.assertRaises(ValueError): native.run_request(request)
        with self.assertRaises(FileExistsError): native.run_request(request)

    # Windows Terminal/pwsh integration — see ci.yml linux job (skips here, runs on the windows job)
    @unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"), "needs Windows + pwsh")
    def test_split_falls_back_to_tab_and_no_parent_status_inheritance(self):
        class Lock:
            def close(self): pass
        calls = []
        def invoke(argv, **kwargs):
            calls.append((argv, kwargs))
            if "sp" in argv: return subprocess.CompletedProcess(argv, 1, "", "")
            session = Path(argv[-1])
            native.save(session.parent / "status.json", {"state": "running"})
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch.object(native, "tool_lock", return_value=Lock()), patch.object(native, "terminal_executable", return_value="wt.exe"), patch.object(native, "powershell", return_value="pwsh.exe"), patch.object(native.subprocess, "run", side_effect=invoke), patch.dict(os.environ, {"WT_SESSION": "test", "FORMIC_STATUS_FILE": "parent"}):
            result = native.launch_session(self.store, "bound", "scanner")
        self.assertEqual(result["mode"], "tab")
        self.assertEqual(len(calls), 2)
        self.assertNotIn("FORMIC_STATUS_FILE", calls[0][1]["env"])

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell integration")
    def test_real_powershell_bridge_with_fake_docker(self):
        result = self.run_real_bridge()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        data = self.store.summary("bound")
        self.assertEqual(data["jobs"][0]["state"], "complete")
        self.assertEqual(data["counts"]["observations"], 1)
        self.assertTrue((self.store.resolve_run_path("bound", data["jobs"][0]["path"]) / "console.log").is_file())

    # Windows Terminal/pwsh integration — see ci.yml linux job (skips here, runs on the windows job)
    @unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"), "needs Windows + pwsh")
    def test_real_powershell_runner_refuses_when_the_sidecar_is_gone(self):
        (self.store.case_dir("bound") / "authorization.json").unlink()
        result = self.run_real_bridge()
        self.assertEqual(result.returncode, 77, result.stdout+result.stderr)
        self.assertEqual(self.store.summary("bound")["counts"]["observations"], 0)

    def route_adapter_gate_environment(self):
        """Isolated LOCALAPPDATA whose scanner-gate.json names the adapter owning the default route, as the gate's own provider resolves it."""
        probe = "$r = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction Stop | Where-Object { $_.InterfaceIndex } | Select-Object -First 1; if ($r) { (Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop).Name }"
        probed = subprocess.run([native.powershell(), "-NoProfile", "-Command", probe], capture_output=True, text=True, timeout=30)
        adapter_name = probed.stdout.strip()
        if probed.returncode != 0 or len(adapter_name) < 3:
            self.skipTest("no default-route adapter name could be probed on this host")
        literal_pattern = adapter_name
        for wildcard_character in "`[]*?":
            literal_pattern = literal_pattern.replace(wildcard_character, "`" + wildcard_character)
        local_app_data = Path(self.tmp.name) / "localappdata"
        (local_app_data / "ScannerLauncher").mkdir(parents=True)
        gate_config = {"schemaVersion": 1, "mode": "vpn", "vpnNamePatterns": [literal_pattern], "proxyUrls": []}
        (local_app_data / "ScannerLauncher" / "scanner-gate.json").write_text(json.dumps(gate_config), encoding="utf-8")
        return {"LOCALAPPDATA": str(local_app_data)}

    def run_real_bridge(self):
        # The actual runner and transcript execute; ONLY docker is replaced by a
        # local stub executable in this child's PATH. No Docker service is used.
        fake = Path(self.tmp.name) / "bin"; fake.mkdir()
        script = fake / "docker_stub.py"
        script.write_text("import os,json,sys\nfrom pathlib import Path\nif 'run' in sys.argv:\n p=Path(os.environ['SCANNER_OUTPUT']);p.mkdir(parents=True,exist_ok=True);p.joinpath('report.json').write_text(json.dumps([{'username':'fixture','site_name':'Example','status':'Found','url':'https://example.test/fixture'}]))\n", encoding="utf-8")
        import sys
        (fake / "docker.cmd").write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
        runtime_file = Path(self.tmp.name) / "runtime.json"
        runtime_file.write_text(json.dumps({"python": sys.executable}), encoding="utf-8")
        env = dict(os.environ, PATH=str(fake)+os.pathsep+os.environ["PATH"], OSINT_CASE_SESSION=str(self.session), OSINT_PROFILER_RUNTIME_FILE=str(runtime_file), **self.route_adapter_gate_environment())
        command = [native.powershell(), "-NoProfile", "-Command", ". '"+str(native.APP / "Invoke-CaseScan.ps1")+"'; Invoke-CaseScan -ScanArguments @('-u','fixture','-f','json','-o','/output/report.json') -TargetLabel fixture; exit $LASTEXITCODE"]
        return subprocess.run(command, cwd=native.APP, env=env, capture_output=True, text=True, timeout=30)


if __name__ == "__main__": unittest.main()
