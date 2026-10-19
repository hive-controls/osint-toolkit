import json
import tempfile
import unittest
from pathlib import Path
from osint_profiler.store import Store
from osint_profiler.adapters import inspect
from osint_profiler.scans import plan_scan

def scan_row(site="SiteA", url="https://a.example/u/alice", status="Found"):
    return {"username": "alice", "site_name": site, "status": status, "url": url, "extra": {}}

class Cases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.store.create_case("sample", "Which accounts are connected?")

    def tearDown(self):
        self.tmp.cleanup()

    def test_inbox_idempotence_and_changed_snapshot(self):
        data = json.dumps([scan_row()]).encode()
        result = self.store.import_bytes(data, "scan.json")
        self.assertEqual(self.store.summary("sample")["counts"]["observations"], 0)
        self.store.assign_import(result["id"], "sample")
        self.store.assign_import(result["id"], "sample")
        updated = self.store.import_bytes(json.dumps([scan_row(), scan_row("SiteB", "https://b.example/alice")]).encode(), "scan.json", "sample")
        summary = self.store.summary("sample")
        self.assertEqual(summary["counts"]["observations"], 2)
        self.assertEqual(summary["counts"]["raw_observations"], 3)
        self.assertEqual(summary["counts"]["artifacts"], 2)
        self.assertEqual(summary["relations"][0]["status"], "proposed")
        self.assertEqual(len(summary["groups"]), 2)
        self.assertNotEqual(updated["id"], result["id"])

    def test_user_declared_grouping_dates_association_and_undo(self):
        a = self.store.add_entity("sample", "persona-a", platform="telegram")["id"]
        b = self.store.add_entity("sample", "persona-b", platform="roblox")["id"]
        c = self.store.add_entity("sample", "seller", kind="person")["id"]
        rid = self.store.add_relation("sample", a, b, "same_entity", "Known by operator", "2026-09-01")["id"]
        self.store.add_relation("sample", b, c, "associated_with")
        self.assertEqual(len(self.store.summary("sample", "2026-08-31")["groups"]), 3)
        self.assertEqual(len(self.store.summary("sample", "2026-09-25")["groups"]), 2)
        self.store.review_relation("sample", rid, "rejected", "Wrong match")
        snap = self.store.summary("sample")
        self.assertEqual(len(snap["groups"]), 3)
        self.store.undo("sample", snap["events"][0]["id"])
        self.assertEqual(len(self.store.summary("sample")["groups"]), 2)

    def test_evidence_contradiction_and_integrity(self):
        a = self.store.add_entity("sample", "a")["id"]
        b = self.store.add_entity("sample", "b")["id"]
        relation = self.store.add_relation("sample", a, b, "same_entity")["id"]
        art = self.store.import_bytes(b"screenshot placeholder", "image.png", "sample")["id"]
        self.store.attach_evidence("sample", relation, art, "contradicts", "region: 0,0,20,20", "Timeline conflict")
        self.assertTrue(self.store.summary("sample")["relations"][0]["has_contradiction"])
        self.assertEqual(self.store.summary("sample")["relations"][0]["status"], "accepted")
        _, path = self.store.artifact("sample", art)
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.store.artifact("sample", art)

    def test_path_scope_and_legacy_notes_preserved(self):
        with self.assertRaises(ValueError): self.store.create_case("../escape", "Question")
        old = Path(self.tmp.name) / "cases" / "legacy"
        old.mkdir(); (old / "case.md").write_text("Original notes", encoding="utf-8")
        self.store.create_case("legacy", "Question", adopt=True)
        self.assertEqual((old / "case.md").read_text(), "Original notes")

    def test_multitarget_selection_and_persistent_rejection(self):
        other = dict(scan_row(), username="bob")
        item = self.store.import_bytes(json.dumps([scan_row(), other]).encode(), "mixed.json")
        self.store.assign_import(item["id"], "sample", ["alice"])
        snapshot = self.store.summary("sample")
        self.assertEqual(len(snapshot["observations"]), 1)
        fp = snapshot["observations"][0]["fingerprint"]
        self.store.review_observation("sample", fp, "excluded", "Wrong person")
        self.store.assign_import(item["id"], "sample", ["alice"])
        self.assertEqual(self.store.summary("sample")["observations"][0]["review_status"], "excluded")

    def test_scan_plan_is_bounded_and_export_safe(self):
        p = plan_scan(self.store, "sample", "maigret", "alice")
        self.assertIn("--no-recursion", p["arguments"])
        self.assertIn("--csv", p["arguments"])
        with self.assertRaises(ValueError): plan_scan(self.store, "sample", "maigret", "--help")
        self.store.add_note("sample", '<script>alert("x")</script>', "allegation")
        export = self.store.export("sample")
        text = Path(export["html"]).read_text(encoding="utf-8")
        self.assertNotIn('<script>alert', text)
        self.assertIn("&lt;script&gt;", text)

class Adapters(unittest.TestCase):
    def test_maigret_json_is_positive_only(self):
        payload = {"Example": {"username": "alice", "url_user": "https://e.example/alice", "status": {"status": "Claimed"}}}
        result = inspect(json.dumps(payload).encode(), "report.json")
        self.assertEqual(result["counts"], {"hit": 1})
        self.assertIn("unknown coverage", result["issues"][-1])

    def test_repeated_csv_headers_and_errors(self):
        data = b"username,site_name,status,url\nalice,A,Error,\nusername,site_name,status,url\nalice,B,Skipped,\n"
        result = inspect(data, "scan.csv")
        self.assertEqual(result["counts"], {"error": 1, "skipped": 1})

    def test_phone_failure_not_absence(self):
        payload = {"tool": "phone-lookup", "local": {"e164": "+15555550123"}, "sources": {"provider": {"ok": False, "hit": False}}}
        result = inspect(json.dumps(payload).encode(), "phone.json")
        self.assertEqual(result["observations"][-1]["status"], "error")

if __name__ == "__main__": unittest.main()
