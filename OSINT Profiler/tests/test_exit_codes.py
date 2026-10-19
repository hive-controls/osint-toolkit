import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import cli, native
from osint_profiler.scans import Scanner, plan_scan
from osint_profiler.store import Store
from authz_support import authorize_case, legacy_json


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def fake_process(exit_code):
    class Process:
        pid = 4242
        def __init__(self, command, **kwargs): pass
        def wait(self, **kwargs): return exit_code
        def poll(self): return exit_code
    return Process


class ScanConfirmExitCodes(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(self.directory.name)
        self.store.create_case("c", "Synthetic")
        authorize_case(self.store, "c")

    def confirm(self, exit_code):
        with patch("osint_profiler.scans.shutil.which", return_value="stub"), \
             patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             patch("osint_profiler.scans.subprocess.Popen", fake_process(exit_code)):
            return run_cli("--root", self.directory.name, "scan", "c", "--tool", "scanner", "--target", "fixture", "--confirm", "RUN", "--json")

    def test_runner_exit_codes_propagate(self):
        for exit_code in (75, 77, 78, 1, 130):
            with self.subTest(exit_code=exit_code):
                self.assertEqual(self.confirm(exit_code)[0], exit_code)

    def test_complete_run_exits_zero(self):
        code, out, _ = self.confirm(0)
        self.assertEqual(code, 0)
        self.assertIn("job_id", out)

    def test_partial_run_is_not_success(self):
        with patch("osint_profiler.scans.envelope.write_result", side_effect=ValueError("forced partial")):
            self.assertEqual(self.confirm(0)[0], 1)


class UsageExitCodes(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        Store(self.directory.name).create_case("c", "Synthetic")

    def scan(self, *extra, json_output=True):
        argv = ["--root", self.directory.name, "scan", "c", *extra]
        return run_cli(*argv, *(["--json"] if json_output else []))

    def test_invalid_target_exits_two_with_usage_error(self):
        code, out, _ = self.scan("--tool", "maigret", "--target=-bad")
        self.assertEqual(code, 2)
        payload = legacy_json(out)
        self.assertEqual(payload["error"], "usage")
        self.assertIn("without whitespace", payload["message"])

    def test_invalid_options_exit_two(self):
        self.assertEqual(self.scan("--tool", "maigret", "--target", "alice", "--top", "0")[0], 2)
        self.assertEqual(self.scan("--tool", "scanner", "--target", "alice", "--modules", "a b")[0], 2)
        self.assertEqual(self.scan("--tool", "phone", "--target", "+15551234567", "--region", "USA")[0], 2)

    def test_usage_error_without_json_goes_to_stderr(self):
        code, out, err = self.scan("--tool", "maigret", "--target=-bad", json_output=False)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Error:", err)

    def test_valid_plan_still_exits_zero(self):
        code, out, _ = self.scan("--tool", "maigret", "--target", "alice")
        self.assertEqual(code, 0)
        self.assertFalse(legacy_json(out)["executed"])

    def test_other_value_errors_keep_exit_one_and_error_shape(self):
        code, out, _ = run_cli("--root", self.directory.name, "scan", "missing", "--tool", "maigret", "--target", "alice", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(list(legacy_json(out)), ["error"])


class LockDirectoriesHonourRoot(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = Store(self.directory.name)
        self.store.create_case("c", "Synthetic")
        authorize_case(self.store, "c")

    def test_scanner_start_locks_under_the_given_root(self):
        with patch("osint_profiler.scans.shutil.which", return_value="stub"), \
             patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             patch("osint_profiler.scans.subprocess.Popen", fake_process(0)):
            Scanner(self.store).start(plan_scan(self.store, "c", "scanner", "fixture"))
        self.assertTrue((self.root / ".profiler-locks" / "scanner.lock").is_file())

    def test_native_tool_lock_uses_the_given_root(self):
        lock = native.tool_lock("maigret", self.root)
        lock.close()
        self.assertTrue((self.root / ".profiler-locks" / "maigret.lock").is_file())


if __name__ == "__main__":
    unittest.main()
