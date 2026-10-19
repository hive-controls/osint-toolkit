import unittest
from osint_profiler.chainrefs import ChainError, parse_input, select_one

ACCEPTED = [
    ("${steps.s1.entities.value}", ("steps", "s1", "entities", None, "value", None, None)),
    ("${steps.s1.entities[kind=username].value}", ("steps", "s1", "entities", "username", "value", None, None)),
    ("${steps.s1.entities[kind=username].value|first}", ("steps", "s1", "entities", "username", "value", None, "first")),
    ("${steps.s-2_x.entities[kind=email].value|only}", ("steps", "s-2_x", "entities", "email", "value", None, "only")),
    ("${steps.s1.entities[kind=phone.e164].value|first}", ("steps", "s1", "entities", "phone.e164", "value", None, "first")),
    ("${steps.s1.entities[kind=account].attrs.site}", ("steps", "s1", "entities", "account", "attrs", "site", None)),
    ("${steps.s1.inputs.value}", ("steps", "s1", "inputs", None, "value", None, None)),
    ("${steps.s1.inputs[kind=username].value|only}", ("steps", "s1", "inputs", "username", "value", None, "only")),
    ("${steps.s1.artifacts[kind=report-json].value|first}", ("steps", "s1", "artifacts", "report-json", "value", None, "first")),
    ("${steps.s1.artifacts[kind=report_json].attrs.sha256|first}", ("steps", "s1", "artifacts", "report_json", "attrs", "sha256", "first")),
    ("${case.entities[kind=email].value|first}", ("case", None, "entities", "email", "value", None, "first")),
    ("${case.entities.value}", ("case", None, "entities", None, "value", None, None)),
    ("${case.inputs[kind=username].value|only}", ("case", None, "inputs", "username", "value", None, "only")),
    ("${case.artifacts.attrs.sha256|first}", ("case", None, "artifacts", None, "attrs", "sha256", "first")),
]

LITERALS = ["alice", "alice@example.test", "+15555550123", "$HOME", "a}b", "{steps.s1}", "cost $5", "steps.s1.entities.value", "$", "{x}"]

REJECTED = [
    "${steps.s1.entities.value",
    "${steps.s1.entities.value}}",
    "x${steps.s1.entities.value}",
    "${steps.s1.entities.value}x",
    "${steps.s1.entities.value} ${steps.s1.entities.value}",
    "${${steps.s1.entities.value}}",
    "${steps.${case.entities.value}.entities.value}",
    "${steps.s1.entities[kind=${case.entities.value}].value}",
    "${steps.s1.entities[kind=username][kind=email].value}",
    "${steps.s1.entities[kind=username].value|first|only}",
    "${steps.s1.entities[kind=username].value|last}",
    "${steps.s1.entities[kind=username].value|upper}",
    "${steps.s1.entities[site=github].value}",
    "${steps.s1.entities[kind!=username].value}",
    "${steps.s1.entities[0].value}",
    "${steps.s1.entities[kind=user name].value}",
    "${steps.s1.entities.value + 1}",
    "${steps.s1.entities.value.upper()}",
    "${steps.s1.entities.label}",
    "${steps.s1.entities.attrs}",
    "${steps.s1.entities.attrs.a.b}",
    "${steps.s1.entities.attrs.}",
    "${steps.s1.notes.value}",
    "${steps.entities.value}",
    "${steps..entities.value}",
    "${steps.S1.entities.value}",
    "${case.s1.entities.value}",
    "${cases.entities.value}",
    "${env.HOME}",
    "${}",
    "${ steps.s1.entities.value }",
    "${steps.s1.entities.value|}",
    "${__import__('os').system('x')}",
    "${steps.s1.entities.value}\n",
]


class ReferenceSyntax(unittest.TestCase):
    def test_accepted_shapes(self):
        self.assertGreaterEqual(len(ACCEPTED), 13)
        for text, shape in ACCEPTED:
            with self.subTest(text=text):
                ref = parse_input(text)
                self.assertEqual((ref.namespace, ref.step, ref.path, ref.kind, ref.terminal, ref.attribute, ref.pipe), shape)

    def test_literals_pass_through(self):
        for text in LITERALS:
            with self.subTest(text=text):
                self.assertIsNone(parse_input(text))

    def test_rejected_forms_are_spec_invalid(self):
        self.assertGreaterEqual(len(REJECTED), 20)
        for text in REJECTED:
            with self.subTest(text=text), self.assertRaises(ChainError) as raised:
                parse_input(text)
            self.assertEqual(raised.exception.code, "spec-invalid")

    def test_nested_reference_is_never_accepted(self):
        for text in ("${a${steps.s1.entities.value}}", "${steps.s1.entities.value${case.entities.value}}"):
            with self.subTest(text=text), self.assertRaises(ChainError):
                parse_input(text)

    def test_non_string_is_spec_invalid(self):
        with self.assertRaises(ChainError):
            parse_input(5)


def candidate(kind, value, **attrs):
    return {"kind": kind, "value": value, "attrs": attrs, "provenance": "user", "from": None}


class Selection(unittest.TestCase):
    ITEMS = [candidate("username", "alpha", site="a"), candidate("username", "beta", site="b"), candidate("email", "e@x.test")]

    def pick(self, text, items=None):
        return select_one(parse_input(text), self.ITEMS if items is None else items)

    def test_first_takes_the_first_match(self):
        self.assertEqual(self.pick("${steps.s.entities[kind=username].value|first}")["value"], "alpha")

    def test_only_accepts_exactly_one(self):
        self.assertEqual(self.pick("${steps.s.entities[kind=email].value|only}")["value"], "e@x.test")

    def test_only_rejects_many_listing_candidates(self):
        with self.assertRaises(ChainError) as raised:
            self.pick("${steps.s.entities[kind=username].value|only}")
        self.assertEqual(raised.exception.code, "ambiguous-input")
        self.assertIn("alpha", str(raised.exception))
        self.assertIn("beta", str(raised.exception))

    def test_many_without_pipe_is_ambiguous(self):
        with self.assertRaises(ChainError) as raised:
            self.pick("${steps.s.entities[kind=username].value}")
        self.assertEqual(raised.exception.code, "ambiguous-input")
        self.assertIn("beta", str(raised.exception))

    def test_single_without_pipe_resolves(self):
        self.assertEqual(self.pick("${steps.s.entities[kind=email].value}")["value"], "e@x.test")

    def test_empty_selection_is_an_error_for_every_pipe(self):
        for pipe in ("", "|first", "|only"):
            with self.subTest(pipe=pipe), self.assertRaises(ChainError) as raised:
                self.pick("${steps.s.entities[kind=phone].value" + pipe + "}")
            self.assertEqual(raised.exception.code, "empty-reference")

    def test_attribute_terminal_skips_entities_without_it(self):
        self.assertEqual(self.pick("${steps.s.entities.attrs.site|first}")["value"], "a")

    def test_attribute_terminal_returns_the_attribute_value(self):
        self.assertEqual(self.pick("${steps.s.entities[kind=username].attrs.site|only}", [candidate("username", "alpha", site="a")])["value"], "a")


if __name__ == "__main__":
    unittest.main()
