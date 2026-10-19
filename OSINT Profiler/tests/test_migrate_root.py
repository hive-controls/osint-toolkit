import contextlib
import hashlib
import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import cli, migrate
from osint_profiler.store import Store
from osint_profiler.util import database, json_text


def tree_hashes(root):
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(Path(root).rglob("*")) if path.is_file()}


class MigrateRootFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.old, self.new = self.base / "old", self.base / "new"
        store = Store(self.old)
        store.create_case("alpha", "Synthetic only")
        run = store.case_dir("alpha") / "runs" / "job1"
        (run / "output").mkdir(parents=True)
        (run / "output" / "results.json").write_text("[]", encoding="utf-8")
        plan = {"case_id": "alpha", "tool": "scanner", "target": "x", "output": str(run / "output")}
        (run / "plan.json").write_text(json_text(plan), encoding="utf-8")
        with database(store.db_path("alpha")) as con:
            con.execute("INSERT INTO jobs(id,tool,target,state,plan,path,started) VALUES(?,?,?,?,?,?,?)",
                        ("job1", "scanner", "x", "complete", json_text(plan), str(run), "2026-01-01T00:00:00+00:00"))
        for lane in ("maigret", "scanner"):
            (self.old / lane).mkdir()
            (self.old / lane / "report.json").write_text(json.dumps({"lane": lane}), encoding="utf-8")
        (self.old / ".profiler-locks").mkdir()
        (self.old / ".profiler-locks" / "scanner.lock").write_bytes(b"0")
        self.before = tree_hashes(self.old)


class MigrateCopies(MigrateRootFixture):
    def test_copy_verify_and_rewrite(self):
        result = migrate.migrate_root(self.old, self.new)
        self.assertEqual(result["corrupt"], [])
        self.assertEqual(result["conflicts"], [])
        self.assertGreater(result["verified"], 0)
        self.assertEqual(result["verified"], result["copied"])
        copied = tree_hashes(self.new)
        self.assertIn("cases/alpha/runs/job1/output/results.json", copied)
        self.assertIn("maigret/report.json", copied)
        self.assertNotIn(".profiler-locks/scanner.lock", copied)
        self.assertEqual(copied["maigret/report.json"], self.before["maigret/report.json"])
        with database(self.new / "cases" / "alpha" / "case.sqlite") as con:
            row = con.execute("SELECT path,plan FROM jobs WHERE id='job1'").fetchone()
        self.assertEqual(row["path"], "runs/job1")
        self.assertEqual(json.loads(row["plan"])["output"], "runs/job1/output")
        plan_file = json.loads((self.new / "cases" / "alpha" / "runs" / "job1" / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan_file["output"], "runs/job1/output")
        self.assertEqual(result["rewritten"], {"jobs": 1, "plans": 1})

    def test_original_is_left_untouched(self):
        migrate.migrate_root(self.old, self.new)
        self.assertEqual(tree_hashes(self.old), self.before)
        with database(self.old / "cases" / "alpha" / "case.sqlite") as con:
            self.assertTrue(con.execute("SELECT path FROM jobs").fetchone()["path"].startswith(str(self.old)))

    def test_copy_does_not_move(self):
        with patch.object(migrate.shutil, "move", side_effect=AssertionError("moved")):
            migrate.migrate_root(self.old, self.new)
        self.assertTrue((self.old / "cases" / "alpha" / "case.sqlite").is_file())
        self.assertTrue((self.new / "cases" / "alpha" / "case.sqlite").is_file())

    def test_rewritten_ledger_still_opens_and_resolves(self):
        migrate.migrate_root(self.old, self.new)
        store = Store(self.new)
        job = store.summary("alpha")["jobs"][0]
        self.assertTrue(store.resolve_run_path("alpha", job["path"]).is_dir())

    def test_refuses_nonempty_target_and_changes_nothing(self):
        (self.new / "cases" / "other").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "already has cases"):
            migrate.migrate_root(self.old, self.new)
        self.assertEqual(sorted(path.name for path in (self.new / "cases").iterdir()), ["other"])

    def test_force_never_deletes_or_overwrites(self):
        (self.new / "cases" / "other").mkdir(parents=True)
        (self.new / "cases" / "other" / "keep.txt").write_text("keep", encoding="utf-8")
        (self.new / "maigret").mkdir()
        (self.new / "maigret" / "report.json").write_text("different", encoding="utf-8")
        result = migrate.migrate_root(self.old, self.new, force=True)
        self.assertEqual((self.new / "cases" / "other" / "keep.txt").read_text(encoding="utf-8"), "keep")
        self.assertEqual((self.new / "maigret" / "report.json").read_text(encoding="utf-8"), "different")
        self.assertEqual(result["conflicts"], ["maigret/report.json"])
        self.assertTrue((self.new / "cases" / "alpha" / "case.sqlite").is_file())

    def test_dry_run_copies_nothing_and_lists_sizes(self):
        result = migrate.migrate_root(self.old, self.new, dry_run=True)
        self.assertFalse(self.new.exists())
        self.assertTrue(result["dry_run"])
        sizes = {item["path"]: item["bytes"] for item in result["files"]}
        self.assertEqual(sizes["maigret/report.json"], len(json.dumps({"lane": "maigret"})))
        self.assertEqual(result["bytes"], sum(sizes.values()))

    def test_corrupted_copy_is_reported(self):
        real = migrate.copy_file

        def flip_a_byte(source, destination):
            real(source, destination)
            if Path(destination).name == "report.json" and "scanner" in str(destination):
                data = bytearray(Path(destination).read_bytes())
                data[0] ^= 0xFF
                Path(destination).write_bytes(bytes(data))
        with patch.object(migrate, "copy_file", flip_a_byte):
            result = migrate.migrate_root(self.old, self.new)
        self.assertEqual(result["corrupt"], ["scanner/report.json"])

    def test_refuses_nested_or_same_roots(self):
        for target in (self.old, self.old / "inside"):
            with self.subTest(target=str(target)), self.assertRaises(ValueError):
                migrate.migrate_root(self.old, target)

    def test_missing_source_is_an_error(self):
        with self.assertRaises(ValueError):
            migrate.migrate_root(self.base / "nope", self.new)


class MigrateCommand(MigrateRootFixture):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_json_summary_and_exit_zero(self):
        code, out, _ = self.run_cli("migrate-root", "--from", str(self.old), "--to", str(self.new), "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)["data"]
        self.assertEqual(data["corrupt"], [])
        self.assertIn("left in place", data["next"])

    def test_dry_run_command_copies_nothing(self):
        code, out, _ = self.run_cli("migrate-root", "--from", str(self.old), "--to", str(self.new), "--dry-run", "--json")
        self.assertEqual(code, 0)
        self.assertFalse(self.new.exists())

    def test_corruption_is_nonzero_and_reported(self):
        real = migrate.copy_file

        def flip(source, destination):
            real(source, destination)
            if Path(destination).name == "report.json":
                Path(destination).write_bytes(b"corrupt")
        with patch.object(migrate, "copy_file", flip):
            code, out, _ = self.run_cli("migrate-root", "--from", str(self.old), "--to", str(self.new), "--json")
        self.assertNotEqual(code, 0)
        self.assertIn("report.json", out)

    def test_refusal_is_nonzero(self):
        (self.new / "cases" / "other").mkdir(parents=True)
        code, out, _ = self.run_cli("migrate-root", "--from", str(self.old), "--to", str(self.new), "--json")
        self.assertNotEqual(code, 0)
        self.assertIn("already has cases", out)


if __name__ == "__main__":
    unittest.main()
