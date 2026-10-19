import json
import tempfile
import unittest
from pathlib import Path
from osint_profiler.scans import plan_scan
from osint_profiler.store import Store

CORPUS = json.loads((Path(__file__).parent / "fixtures" / "plan_scan_golden.json").read_text(encoding="utf-8"))
PLAN_FIELDS = ("tool", "target", "kind", "top", "region", "modules", "arguments")


class PlanScanGolden(unittest.TestCase):
    """Characterization of plan_scan captured from the pre-catalog implementation."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.store = Store(cls.directory.name)
        cls.store.create_case("golden", "Synthetic golden corpus")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_corpus_is_large_enough(self):
        self.assertGreaterEqual(len(CORPUS), 40)
        self.assertTrue(any(c["expected"]["ok"] for c in CORPUS))
        self.assertTrue(any(not c["expected"]["ok"] for c in CORPUS))

    def test_every_case_matches_recorded_behavior(self):
        for case in CORPUS:
            with self.subTest(case=case["name"]):
                expected = case["expected"]
                if expected["ok"]:
                    plan = plan_scan(self.store, "golden", **case["inputs"])
                    self.assertEqual({k: plan[k] for k in PLAN_FIELDS}, {k: expected[k] for k in PLAN_FIELDS})
                else:
                    with self.assertRaises(ValueError) as raised:
                        plan_scan(self.store, "golden", **case["inputs"])
                    self.assertEqual(type(raised.exception).__name__, expected["error_type"])
                    self.assertEqual(str(raised.exception), expected["message"])


if __name__ == "__main__":
    unittest.main()
