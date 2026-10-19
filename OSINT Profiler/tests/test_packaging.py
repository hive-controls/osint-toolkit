import os
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import cli, util

PROFILER = Path(__file__).resolve().parents[1]
TOOLKIT = PROFILER.parent
PROJECT = tomllib.loads((PROFILER / "pyproject.toml").read_text(encoding="utf-8"))["project"]


class Metadata(unittest.TestCase):
    def test_distribution_identity_and_runtime_stays_stdlib_only(self):
        self.assertEqual(PROJECT["name"], "osint-casework")
        self.assertEqual(PROJECT["requires-python"], ">=3.11")
        self.assertEqual(PROJECT["dependencies"], [])
        self.assertEqual(PROJECT["license"], "Apache-2.0")

    def test_console_script_targets_a_real_wrapper_that_exits_with_the_int(self):
        self.assertEqual(PROJECT["scripts"], {"osint-case": "osint_profiler.cli:console_main"})
        with patch.object(cli, "main", return_value=77):
            with self.assertRaises(SystemExit) as caught:
                cli.console_main()
        self.assertEqual(caught.exception.code, 77)

    def test_acknowledgement_is_one_file_shared_with_the_powershell_side(self):
        config = tomllib.loads((PROFILER / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertIn("ACKNOWLEDGEMENT.txt", config["tool"]["setuptools"]["package-data"]["osint_profiler"])
        self.assertEqual(len(list(TOOLKIT.rglob("ACKNOWLEDGEMENT.txt"))), 1)
        powershell = (TOOLKIT / "shared" / "OsintSubjectAuthorization.ps1").read_text(encoding="utf-8")
        self.assertIn(r"OSINT Profiler\osint_profiler\ACKNOWLEDGEMENT.txt", powershell)


class ToolkitRootSeam(unittest.TestCase):
    def test_default_derivation_is_the_checkout(self):
        with patch.dict(os.environ):
            os.environ.pop("OSINT_TOOLKIT_ROOT", None)
            self.assertEqual((util.toolkit_root(), util.app_dir()), (TOOLKIT, PROFILER))

    def test_env_points_an_installed_copy_at_another_toolkit(self):
        with patch.dict(os.environ, {"OSINT_TOOLKIT_ROOT": str(TOOLKIT)}):
            self.assertEqual(util.app_dir(), TOOLKIT / "OSINT Profiler")
        elsewhere = TOOLKIT.parent
        with patch.dict(os.environ, {"OSINT_TOOLKIT_ROOT": str(elsewhere)}):
            self.assertEqual((util.toolkit_root(), util.app_dir()), (elsewhere.resolve(), elsewhere.resolve() / "OSINT Profiler"))


if __name__ == "__main__":
    unittest.main()
