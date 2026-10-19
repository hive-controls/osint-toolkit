import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import catalog, scans
from osint_profiler.scans import plan_scan
from osint_profiler.store import Store
from osint_profiler.util import WORKSPACE


def copy_catalog(destination):
    shutil.copytree(WORKSPACE / "shared" / "catalog", Path(destination) / "shared" / "catalog")
    return Path(destination)


def edit_catalog(root, mutate):
    path = Path(root) / "shared" / "catalog" / "tools.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")


class CatalogLoading(unittest.TestCase):
    def test_shipped_catalog_loads_and_lists_expected_tools(self):
        loaded = catalog.load_catalog()
        self.assertEqual([t["id"] for t in loaded["tools"]], ["maigret", "user-scanner", "phone-lookup", "osint-case", "torbot"])
        self.assertEqual(loaded["catalog_version"], "1")

    def test_invalid_catalog_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_catalog(tmp)
            edit_catalog(root, lambda data: data["tools"][0].pop("runner"))
            with self.assertRaises(catalog.CatalogError):
                catalog.load_catalog(root)

    def test_missing_catalog_raises(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(catalog.CatalogError):
            catalog.load_catalog(tmp)

    def test_toolkit_root_environment_seam(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_catalog(tmp)
            edit_catalog(root, lambda data: data.update(catalog_version="9"))
            with patch.dict("os.environ", {"OSINT_TOOLKIT_ROOT": str(root)}):
                self.assertEqual(catalog.load_catalog()["catalog_version"], "9")
            self.assertEqual(catalog.load_catalog()["catalog_version"], "1")

    def test_lookup_accepts_canonical_and_legacy_ids(self):
        self.assertEqual(catalog.tool("user-scanner")["id"], "user-scanner")
        self.assertEqual(catalog.tool("scanner")["id"], "user-scanner")
        self.assertEqual(catalog.tool("phone")["id"], "phone-lookup")
        self.assertIsNone(catalog.tool("nope"))

    def test_torbot_is_interactive_only_and_not_a_scan_tool(self):
        self.assertTrue(catalog.tool("torbot")["interactive_only"])
        self.assertNotIn("torbot", scans.TOOLS)
        self.assertEqual(sorted(scans.TOOLS), ["maigret", "phone", "scanner"])
        self.assertEqual(scans.TOOLS["scanner"], ("User-Scanner Docker", "run-scanner.ps1", "SCANNER_OUTPUT"))

    def test_versions_come_from_the_catalog(self):
        self.assertEqual({t: catalog.tool(t)["version"] for t in ("maigret", "scanner", "phone")},
                         {"maigret": "0.6.4", "scanner": "1.5.1.3", "phone": "0.1.0"})


class BuildArgv(unittest.TestCase):
    def test_maigret_argv(self):
        argv = catalog.build_argv(catalog.tool("maigret"), {"target": "alice", "kind": "username"}, {"top": 7})
        self.assertEqual(argv, ["alice", "--top-sites", "7", "--no-recursion", "-J", "simple", "--csv", "-M"])

    def test_optional_segment_omitted_when_option_empty(self):
        argv = catalog.build_argv(catalog.tool("phone"), {"target": "+15551234567", "kind": "phone"}, {"region": ""})
        self.assertEqual(argv, ["+15551234567"])

    def test_transform_and_kind_flag(self):
        phone = catalog.build_argv(catalog.tool("phone"), {"target": "+15551234567", "kind": "phone"}, {"region": "gb"})
        self.assertEqual(phone[-2:], ["--region", "GB"])
        scanner = catalog.build_argv(catalog.tool("scanner"), {"target": "a@b.test", "kind": "email"}, {"modules": "x,y"})
        self.assertEqual(scanner[:2], ["-e", "a@b.test"])
        self.assertEqual(scanner[-2:], ["-m", "x,y"])

    def test_unknown_placeholder_is_an_error(self):
        entry = {"fixed_argv": [], "inputs": [], "options": [], "argv_template": [{"when": None, "tokens": ["{ghost}"]}]}
        with self.assertRaises(ValueError):
            catalog.build_argv(entry, {"target": "x", "kind": "username"}, {})


class PlanScanIsCatalogDriven(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(self.directory.name)
        self.store.create_case("c", "Synthetic")

    def test_canonical_ids_plan_like_legacy_ids(self):
        for canonical, legacy, target in (("user-scanner", "scanner", "alice"), ("phone-lookup", "phone", "+15551234567")):
            with self.subTest(canonical=canonical):
                new, old = plan_scan(self.store, "c", canonical, target), plan_scan(self.store, "c", legacy, target)
                self.assertEqual(new, old)
                self.assertEqual(new["tool"], legacy)

    def test_interactive_only_tool_is_refused_with_the_historic_message(self):
        with self.assertRaisesRegex(ValueError, "^Choose maigret, scanner, or phone.$"):
            plan_scan(self.store, "c", "torbot", "example.onion")

    def test_catalog_pattern_edit_changes_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_catalog(tmp)
            def tighten(data):
                data["tools"][2]["inputs"][0]["pattern"] = "\\+?[0-9().-]{4,8}"
            edit_catalog(root, tighten)
            with patch.dict("os.environ", {"OSINT_TOOLKIT_ROOT": str(root)}):
                with self.assertRaises(ValueError):
                    plan_scan(self.store, "c", "phone", "+15551234567")
                self.assertEqual(plan_scan(self.store, "c", "phone", "1234")["arguments"], ["1234"])
            self.assertEqual(plan_scan(self.store, "c", "phone", "+15551234567")["arguments"], ["+15551234567"])

    def test_catalog_bound_edit_changes_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = copy_catalog(tmp)
            edit_catalog(root, lambda data: data["tools"][0]["options"][0].update(max=20))
            with patch.dict("os.environ", {"OSINT_TOOLKIT_ROOT": str(root)}):
                with self.assertRaises(ValueError):
                    plan_scan(self.store, "c", "maigret", "alice", top=21)


if __name__ == "__main__":
    unittest.main()
