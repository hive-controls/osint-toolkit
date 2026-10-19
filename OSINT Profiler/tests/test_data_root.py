import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import cli, native, scans, util
from osint_profiler.store import Store


def clean_environment(**overrides):
    keep = {key: value for key, value in os.environ.items() if key not in ("OSINT_ROOT", "XDG_DATA_HOME", "LOCALAPPDATA")}
    keep.update(overrides)
    return patch.dict(os.environ, keep, clear=True)


class DataRootResolution(unittest.TestCase):
    """explicit (--root) > OSINT_ROOT > platform default, for both the nt default and the XDG seam."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def environment_for(self, os_name, with_env):
        values = {"LOCALAPPDATA": str(self.base / "local"), "XDG_DATA_HOME": str(self.base / "xdg"), "HOME": str(self.base / "home"), "USERPROFILE": str(self.base / "home")}
        if with_env:
            values["OSINT_ROOT"] = str(self.base / "from-env")
        return clean_environment(**values)

    def default_for(self, os_name):
        return (self.base / "local" / "OsintToolkit" / "data") if os_name == "nt" else (self.base / "xdg" / "osint-toolkit")

    def test_matrix(self):
        for os_name in ("nt", "posix"):
            for with_env in (False, True):
                for explicit in (None, str(self.base / "from-flag")):
                    with self.subTest(os_name=os_name, env=with_env, explicit=bool(explicit)), self.environment_for(os_name, with_env):
                        expected = (self.base / "from-flag") if explicit else (self.base / "from-env") if with_env else self.default_for(os_name)
                        self.assertEqual(util.data_root(explicit, os_name=os_name), expected)

    def test_explicit_beats_environment(self):
        with self.environment_for("nt", True):
            self.assertEqual(util.data_root(str(self.base / "flag")), self.base / "flag")

    def test_xdg_falls_back_to_home_local_share(self):
        with clean_environment(HOME=str(self.base / "home"), USERPROFILE=str(self.base / "home")):
            self.assertEqual(util.data_root(os_name="posix"), self.base / "home" / ".local" / "share" / "osint-toolkit")

    def test_default_is_not_inside_the_repo(self):
        with clean_environment(LOCALAPPDATA=str(self.base / "local")):
            self.assertFalse(util.data_root(os_name="nt").is_relative_to(util.WORKSPACE))

    def test_store_uses_resolution(self):
        with self.environment_for("nt", True):
            self.assertEqual(Store().root, self.base / "from-env")
            self.assertEqual(Store(str(self.base / "flag")).root, self.base / "flag")


class RootFollowers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_lock_dirs_follow_the_root(self):
        toolkit = self.base / "toolkit"
        (toolkit / "OSINT").mkdir(parents=True)
        store = Store(self.base / "data")
        with patch.object(util, "WORKSPACE", toolkit), patch.object(native, "WORKSPACE", toolkit):
            native.tool_lock("maigret", store.root).close()
            self.assertTrue((store.root / ".profiler-locks" / "maigret.lock").is_file())
            self.assertFalse((util.WORKSPACE / "OSINT" / ".profiler-locks" / "maigret.lock").exists())
            self.assertFalse((native.WORKSPACE / "OSINT" / ".profiler-locks").exists())

    def test_scan_lock_dir_follows_the_root(self):
        source = Path(scans.__file__).read_text(encoding="utf-8")
        self.assertIn("self.store.root / \".profiler-locks\"", source)

    def test_discover_lanes_follow_the_root(self):
        store = Store(self.base / "data")
        (store.root / "maigret").mkdir()
        (store.root / "maigret" / "report.json").write_text("{}", encoding="utf-8")
        self.assertEqual([item["lane"] for item in store.discover()], ["maigret"])
        self.assertTrue(Path(store.discover()[0]["path"]).is_relative_to(store.root))

    def test_web_messages_do_not_hardcode_the_repo_tree(self):
        source = (Path(util.__file__).parent / "web.py").read_text(encoding="utf-8")
        self.assertNotIn("OSINT/.profiler", source)


class LegacyDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.toolkit = self.base / "toolkit"
        self.legacy_cases = self.toolkit / "OSINT" / "cases"
        self.legacy_cases.mkdir(parents=True)
        self.new_root = self.base / "data"

    def warning(self):
        with clean_environment(OSINT_TOOLKIT_ROOT=str(self.toolkit)):
            return util.legacy_data_warning(self.new_root)

    def test_silent_without_legacy_cases(self):
        self.assertIsNone(self.warning())

    def test_silent_when_only_the_shipped_template_exists(self):
        (self.legacy_cases / "_template").mkdir()
        self.assertIsNone(self.warning())

    def test_fires_when_legacy_present_and_new_empty(self):
        (self.legacy_cases / "case-one").mkdir()
        message = self.warning()
        self.assertIn("osint-case migrate-root", message)
        self.assertIn("Legacy case data found", message)

    def test_silent_when_new_root_has_cases(self):
        (self.legacy_cases / "case-one").mkdir()
        (self.new_root / "cases" / "other").mkdir(parents=True)
        self.assertIsNone(self.warning())

    def test_silent_when_root_is_the_legacy_tree(self):
        (self.legacy_cases / "case-one").mkdir()
        with clean_environment(OSINT_TOOLKIT_ROOT=str(self.toolkit)):
            self.assertIsNone(util.legacy_data_warning(self.toolkit / "OSINT"))

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with clean_environment(OSINT_TOOLKIT_ROOT=str(self.toolkit)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_cli_warns_once_on_stderr(self):
        (self.legacy_cases / "case-one").mkdir()
        code, out, err = self.run_cli("--root", str(self.new_root), "list", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(err.count("osint-case migrate-root"), 1)
        self.assertNotIn("migrate-root", out)

    def test_cli_silent_when_new_root_populated(self):
        (self.legacy_cases / "case-one").mkdir()
        (self.new_root / "cases" / "other").mkdir(parents=True)
        self.assertNotIn("migrate-root", self.run_cli("--root", str(self.new_root), "list", "--json")[2])

    def test_doctor_reports_storage_and_legacy(self):
        (self.legacy_cases / "case-one").mkdir()
        code, out, err = self.run_cli("--root", str(self.new_root), "doctor", "--json")
        report = json.loads(out)["data"]
        self.assertEqual(report["storage"], str(self.new_root))
        self.assertTrue(report["legacy_data"]["found"])
        self.assertIn("migrate-root", report["legacy_data"]["next"])


if __name__ == "__main__":
    unittest.main()
