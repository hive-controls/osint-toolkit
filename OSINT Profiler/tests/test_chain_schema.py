import copy
import json
import unittest
from osint_profiler.schemacheck import validate
from osint_profiler.util import WORKSPACE

SCHEMA_PATH = WORKSPACE / "shared" / "catalog" / "schema" / "chain.schema.json"
VALID = {"version": 1, "id": "chain-one", "case_id": "case-a",
         "steps": [{"id": "s1", "tool": "maigret", "inputs": {"target": "alice"}, "options": {"top": 50}},
                   {"id": "s2", "tool": "user-scanner", "inputs": {"target": "${steps.s1.entities[kind=username].value|first}"},
                    "derived_ok": True, "on_error": "continue"}]}


def mutated(change):
    spec = copy.deepcopy(VALID)
    change(spec)
    return spec


REJECTED = {
    "version-two": lambda s: s.update(version=2),
    "missing-id": lambda s: s.pop("id"),
    "missing-case": lambda s: s.pop("case_id"),
    "missing-steps": lambda s: s.pop("steps"),
    "empty-steps": lambda s: s.update(steps=[]),
    "extra-top-level": lambda s: s.update(extra=1),
    "bad-chain-id": lambda s: s.update(id="Bad Id"),
    "step-missing-tool": lambda s: s["steps"][0].pop("tool"),
    "step-missing-inputs": lambda s: s["steps"][0].pop("inputs"),
    "step-extra-key": lambda s: s["steps"][0].update(fanout=True),
    "input-not-string": lambda s: s["steps"][0]["inputs"].update(target=5),
    "input-empty-string": lambda s: s["steps"][0]["inputs"].update(target=""),
    "derived-ok-not-bool": lambda s: s["steps"][0].update(derived_ok="yes"),
    "on-error-unknown": lambda s: s["steps"][0].update(on_error="retry"),
    "options-not-object": lambda s: s["steps"][0].update(options=[]),
    "bad-step-id": lambda s: s["steps"][0].update(id="-x"),
}


class ChainSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_valid_spec_is_accepted(self):
        self.assertEqual(validate(VALID, self.schema), [])

    def test_minimal_step_is_accepted(self):
        spec = {"version": 1, "id": "c", "case_id": "k", "steps": [{"id": "a", "tool": "maigret", "inputs": {"target": "x"}}]}
        self.assertEqual(validate(spec, self.schema), [])

    def test_rejections(self):
        for name, change in REJECTED.items():
            with self.subTest(name=name):
                self.assertTrue(validate(mutated(change), self.schema), name)


if __name__ == "__main__":
    unittest.main()
