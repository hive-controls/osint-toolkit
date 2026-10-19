import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import api
from osint_profiler.scans import Scanner, plan_scan
from osint_profiler.store import Store
from osint_profiler.util import database, json_text
from authz_support import authorize_case


class FakeProcess:
    pid = 4242

    def __init__(self, command, **kwargs):
        Path(kwargs["env"]["SCANNER_OUTPUT"]).joinpath("results.json").write_text(
            json.dumps([{"username": "fixture", "site_name": "Example", "status": "Found", "url": "https://example.test/fixture"}]))

    def wait(self, **kwargs):
        return 0

    def poll(self):
        return 0


def run_fixture_scan(store, case_id):
    with patch("osint_profiler.scans.shutil.which", return_value="stub"), \
            patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
            patch("osint_profiler.scans.subprocess.Popen", FakeProcess):
        return Scanner(store).start(plan_scan(store, case_id, "scanner", "fixture"))


class RunPathsAreRelative(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(self.tmp.name)
        self.store.create_case("paths", "Synthetic only")
        authorize_case(self.store, "paths")

    def test_new_rows_and_plan_json_are_relative(self):
        result = run_fixture_scan(self.store, "paths")
        job_id = result["job_id"]
        with database(self.store.db_path("paths")) as con:
            row = con.execute("SELECT path,plan FROM jobs WHERE id=?", (job_id,)).fetchone()
        self.assertEqual(row["path"], f"runs/{job_id}")
        self.assertEqual(json.loads(row["plan"])["output"], f"runs/{job_id}/output")
        plan_file = json.loads((Path(result["folder"]) / "plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan_file["output"], f"runs/{job_id}/output")

    def test_runner_still_receives_an_absolute_output_directory(self):
        seen = []

        class Recording(FakeProcess):
            def __init__(self, command, **kwargs):
                seen.append(kwargs["env"]["SCANNER_OUTPUT"])
                super().__init__(command, **kwargs)
        with patch("osint_profiler.scans.shutil.which", return_value="stub"), \
                patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                patch("osint_profiler.scans.subprocess.Popen", Recording):
            Scanner(self.store).start(plan_scan(self.store, "paths", "scanner", "fixture"))
        self.assertTrue(Path(seen[0]).is_absolute())

    def test_old_absolute_rows_still_resolve(self):
        folder = self.store.case_dir("paths") / "runs" / "legacyjob"
        (folder / "output").mkdir(parents=True)
        (folder / "result.json").write_text(json.dumps({"schema": "x"}), encoding="utf-8")
        plan = {"case_id": "paths", "tool": "scanner", "target": "old", "output": str(folder / "output")}
        with database(self.store.db_path("paths")) as con:
            con.execute("INSERT INTO jobs(id,tool,target,state,plan,path,started) VALUES(?,?,?,?,?,?,?)",
                        ("legacyjob", "scanner", "old", "complete", json_text(plan), str(folder), "2026-01-01T00:00:00+00:00"))
        job = self.store.summary("paths")["jobs"][0]
        self.assertEqual(job["path"], "runs/legacyjob")
        self.assertEqual(job["plan"]["output"], "runs/legacyjob/output")
        self.assertEqual(self.store.resolve_run_path("paths", str(folder)), folder)
        self.assertEqual(self.store.resolve_run_path("paths", "runs/legacyjob"), folder)
        detail = api.open_case("paths", store=self.store).job_detail("legacyjob")
        self.assertEqual(detail["result"], {"schema": "x"})

    def test_relocated_absolute_rows_resolve_by_runs_segment(self):
        elsewhere = Path(self.tmp.name) / "somewhere-else" / "cases" / "paths" / "runs" / "movedjob"
        with database(self.store.db_path("paths")) as con:
            con.execute("INSERT INTO jobs(id,tool,target,state,plan,path,started) VALUES(?,?,?,?,?,?,?)",
                        ("movedjob", "scanner", "t", "complete", json_text({"output": str(elsewhere / "output")}), str(elsewhere), "2026-01-01T00:00:00+00:00"))
        job = self.store.summary("paths")["jobs"][0]
        self.assertEqual(job["path"], "runs/movedjob")

    def test_new_job_detail_reads_through_the_relative_path(self):
        result = run_fixture_scan(self.store, "paths")
        detail = api.open_case("paths", store=self.store).job_detail(result["job_id"])
        self.assertEqual(detail["path"], f"runs/{result['job_id']}")
        self.assertIsNotNone(detail["result"])


if __name__ == "__main__":
    unittest.main()
