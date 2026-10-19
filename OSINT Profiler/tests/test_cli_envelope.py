import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import cli, errors
from osint_profiler.schemacheck import validate
from osint_profiler.store import Store
from authz_support import authorize_case

TOOLKIT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((TOOLKIT / "shared" / "catalog" / "schema" / "cli-envelope.schema.json").read_text(encoding="utf-8"))


def run_cli(*argv, tty=False):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch("sys.stdin", io.StringIO()):
        with patch("sys.stdin.isatty", return_value=tty, create=True):
            code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def parse_envelope(testcase, out):
    envelope = json.loads(out)
    testcase.assertEqual(validate(envelope, SCHEMA), [], out)
    testcase.assertEqual(envelope["ok"], envelope["error"] is None)
    return envelope


class EnvelopeCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = self.directory.name
        self.store = Store(self.root)
        self.store.create_case("c", "Synthetic")
        authorize_case(self.store, "c")

    def call(self, *argv, tty=False):
        code, out, err = run_cli("--root", self.root, *argv, "--json", tty=tty)
        return code, parse_envelope(self, out), err

    def assert_table_exit(self, code, envelope):
        expected = 0 if envelope["ok"] else errors.exit_code_for(envelope["error"]["code"])
        self.assertEqual(code, expected)


class EveryCommandYieldsAnEnvelope(EnvelopeCase):
    def test_commands(self):
        entity_a = self.store.add_entity("c", "A")["id"]
        entity_b = self.store.add_entity("c", "B")["id"]
        relation = self.store.add_relation("c", entity_a, entity_b, "associated_with")["id"]
        chain_spec = Path(self.root) / "chain.json"
        chain_spec.write_text(json.dumps({"version": 1, "id": "k1", "case_id": "c", "steps": [{"id": "s1", "tool": "maigret", "inputs": {"target": "alice"}}]}), encoding="utf-8")
        commands = [
            ["list"], ["summary", "c"], ["export", "c"], ["inbox"], ["discover"], ["authorize", "c", "--show"],
            ["entity", "c", "--label", "Lbl"], ["note", "c", "--text", "n"], ["link", "c", "--source", entity_a, "--target", entity_b],
            ["review", "c", "--relation", relation, "--status", "accepted"], ["append", "c", "--note", "x"],
            ["scan", "c", "--tool", "maigret", "--target", "alice"], ["chain", "list"], ["chain", "run", str(chain_spec), "--dry-run"],
            ["chain", "show", "nope"], ["summary", "missing"], ["import", str(Path(self.root) / "absent.json")],
            ["assign", "nope", "c"], ["new", "c", "--question", "dup"], ["ui-stop"], ["evidence", "c", "--relation", relation, "--artifact", "nope"],
            ["scan", "c", "--tool", "maigret", "--target=-bad"],
        ]
        for argv in commands:
            with self.subTest(argv=argv):
                code, envelope, _ = self.call(*argv)
                self.assert_table_exit(code, envelope)

    def test_doctor_is_an_envelope(self):
        code, out, _ = run_cli("doctor", "--offline", "--json")
        self.assertEqual(code, 0)
        self.assertTrue(parse_envelope(self, out)["data"]["offline"])

    def test_success_data_is_the_old_payload(self):
        _, envelope, _ = self.call("list")
        self.assertEqual([case["id"] for case in envelope["data"]], ["c"])

    def test_stray_stdout_prints_are_diverted_under_json(self):
        original = cli.Store.summary
        def noisy(store, case_id, as_of=None):
            print("banner that must not reach stdout")
            return original(store, case_id, as_of)
        with patch.object(cli.Store, "summary", noisy):
            code, out, err = run_cli("--root", self.root, "summary", "c", "--json")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["ok"])
        self.assertIn("banner", err)

    def test_failure_carries_deprecated_legacy_error(self):
        _, envelope, _ = self.call("scan", "c", "--tool", "maigret", "--target=-bad")
        self.assertEqual(envelope["error"]["code"], "usage")
        self.assertEqual(envelope["legacy_error"]["error"], "usage")
        self.assertIn("without whitespace", envelope["legacy_error"]["message"])

    def test_missing_case_is_not_found_exit_one(self):
        code, envelope, _ = self.call("summary", "missing")
        self.assertEqual((code, envelope["error"]["code"]), (1, "not-found"))

    def test_authorization_required_is_exit_77_with_details(self):
        self.store.create_case("bare", "No attestation")
        code, envelope, _ = self.call("scan", "bare", "--tool", "scanner", "--target", "fixture", "--confirm", "RUN")
        self.assertEqual((code, envelope["error"]["code"]), (77, "subject-authorization-required"))
        self.assertEqual(envelope["error"]["details"]["reason"], "missing")

    def test_argparse_errors_become_usage_envelopes_under_json(self):
        code, out, _ = run_cli("--root", self.root, "note", "c", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(parse_envelope(self, out)["error"]["code"], "usage")

    def test_argparse_errors_without_json_keep_stderr_usage(self):
        code, out, err = run_cli("--root", self.root, "note", "c")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--text", err)


class NeverPrompts(EnvelopeCase):
    def forbid_prompt(self):
        def refuse(*args, **kwargs):
            raise AssertionError("prompted")
        return [patch.dict(os.environ, {"OSINT_PLAIN_TERMINAL": "1"}), patch.object(cli, "ask", refuse), patch("osint_profiler.terminal.input", refuse, create=True), patch("builtins.input", refuse)]

    def run_forbidding_prompts(self, *argv, tty=True):
        patches = self.forbid_prompt()
        for item in patches: item.start()
        try:
            return self.call(*argv, tty=tty)
        finally:
            for item in patches: item.stop()

    def test_new_without_question_under_json_is_usage_even_on_a_tty(self):
        code, envelope, _ = self.run_forbidding_prompts("new", "fresh")
        self.assertEqual((code, envelope["error"]["code"]), (2, "usage"))

    def test_new_without_case_id_is_usage(self):
        code, envelope, _ = self.run_forbidding_prompts("new", "--question", "q")
        self.assertEqual((code, envelope["error"]["code"]), (2, "usage"))

    def test_other_interactive_entry_points_are_usage(self):
        for argv in (["append", "c"], ["scan", "c"], ["authorize", "c"], ["open", "c"]):
            with self.subTest(argv=argv):
                code, envelope, _ = self.run_forbidding_prompts(*argv)
                self.assertEqual((code, envelope["error"]["code"]), (2, "usage"))

    def test_no_input_flag_blocks_prompts_without_json(self):
        patches = self.forbid_prompt()
        for item in patches: item.start()
        try:
            code, out, err = run_cli("--root", self.root, "new", "fresh", "--no-input", tty=True)
        finally:
            for item in patches: item.stop()
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Error:", err)

    def test_inline_authorization_prompt_is_refused_under_json(self):
        self.store.create_case("bare", "No attestation")
        code, envelope, _ = self.run_forbidding_prompts("scan", "bare", "--tool", "scanner", "--target", "fixture", "--confirm", "RUN")
        self.assertEqual((code, envelope["error"]["code"]), (77, "subject-authorization-required"))

    def test_subprocess_with_stdin_closed_never_hangs(self):
        environment = {**os.environ, "PYTHONPATH": str(Path(cli.__file__).parents[1])}
        for argv in (["new", "fresh", "--json"], ["authorize", "c", "--json"], ["append", "c", "--json"]):
            with self.subTest(argv=argv):
                done = subprocess.run([sys.executable, "-m", "osint_profiler", "--root", self.root, *argv], stdin=subprocess.DEVNULL,
                                      capture_output=True, text=True, timeout=60, env=environment)
                self.assertEqual(done.returncode, 2, done.stderr)
                self.assertEqual(json.loads(done.stdout)["error"]["code"], "usage")


class ErrorTable(unittest.TestCase):
    def test_required_codes_and_exit_values(self):
        expected = {"usage": 2, "not-found": 1, "subject-authorization-required": 77, "network-gate": 75, "config-provider": 78,
                    "interrupted": 130, "derived-input-refused": 2, "spec-invalid": 2, "ambiguous-input": 2}
        for code, exit_code in expected.items():
            self.assertEqual(errors.exit_code_for(code), exit_code)

    def test_every_chain_error_code_is_in_the_table(self):
        source = "".join(path.read_text(encoding="utf-8") for path in Path(cli.__file__).parent.glob("chain*.py"))
        import re
        for code in set(re.findall(r'ChainError\("([a-z-]+)"', source)):
            self.assertIn(code, errors.EXIT_CODES)


if __name__ == "__main__":
    unittest.main()
