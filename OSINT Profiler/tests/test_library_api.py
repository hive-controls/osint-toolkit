import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import api, errors
from osint_profiler.authorization import REQUIRED_PHRASE, AuthorizationRequired
from osint_profiler.chainrefs import ChainError
from osint_profiler.store import Store
from osint_profiler.util import database
from authz_support import FIXTURE_FIELDS, authorize_case
from test_chains import Hops, spec_of, step

TOOLKIT = Path(__file__).resolve().parents[2]


class ApiCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = self.directory.name
        self.store = Store(self.root)
        self.store.create_case("c", "Synthetic")
        self.case = api.open_case("c", root=self.root)
        silence = contextlib.redirect_stdout(io.StringIO())
        silence.__enter__()
        self.addCleanup(silence.__exit__, None, None, None)
        refuse = patch("builtins.input", side_effect=AssertionError("the library API must never prompt"))
        refuse.start()
        self.addCleanup(refuse.stop)

    def authorization_rows(self):
        with database(self.store.db_path("c")) as con:
            return con.execute("SELECT COUNT(*) FROM authorizations").fetchone()[0]


class OpenAndRead(ApiCase):
    def test_catalog_and_summary_and_authorization(self):
        self.assertIn("maigret", [entry["id"] for entry in api.catalog()["tools"]])
        self.assertEqual(self.case.summary()["case"]["id"], "c")
        self.assertEqual(self.case.authorization()["status"], "missing")
        self.assertEqual(self.case.jobs(), [])

    def test_open_case_missing_is_not_found(self):
        with self.assertRaises(errors.NotFoundError) as caught:
            api.open_case("absent", root=self.root)
        self.assertEqual(caught.exception.code, "not-found")


class Authorize(ApiCase):
    def test_wrong_phrase_raises_and_writes_nothing(self):
        for phrase in ("", "i authorize this case", REQUIRED_PHRASE + " ", None):
            with self.subTest(phrase=phrase):
                with self.assertRaises(errors.UsageError):
                    self.case.authorize(**{**FIXTURE_FIELDS, "acknowledgement": phrase})
        self.assertEqual(self.authorization_rows(), 0)
        self.assertEqual(self.case.authorization()["status"], "missing")

    def test_exact_phrase_records_an_attestation(self):
        result = self.case.authorize(**FIXTURE_FIELDS, acknowledgement=REQUIRED_PHRASE)
        self.assertEqual(self.authorization_rows(), 1)
        self.assertEqual(self.case.authorization()["status"], "valid")
        self.assertEqual(result["subject_label"], "Subject A")

    def test_phrase_has_no_default(self):
        with self.assertRaises(TypeError):
            self.case.authorize(**FIXTURE_FIELDS)

    def test_invalid_fields_are_usage_errors(self):
        with self.assertRaises(errors.UsageError):
            self.case.authorize(**{**FIXTURE_FIELDS, "purpose": "bogus"}, acknowledgement=REQUIRED_PHRASE)
        self.assertEqual(self.authorization_rows(), 0)


class PlanAndRun(ApiCase):
    def setUp(self):
        super().setUp()
        authorize_case(self.store, "c")

    def test_plan_is_a_plain_dict_with_gates(self):
        plan = self.case.plan("maigret", "alice", top=5)
        self.assertEqual((plan["tool"], plan["confirm_required"], plan["authorization"]["status"]), ("maigret", "RUN", "valid"))

    def test_bad_target_is_a_usage_error(self):
        with self.assertRaises(errors.UsageError):
            self.case.plan("maigret", "-bad")

    def test_run_requires_the_exact_confirmation(self):
        plan = self.case.plan("maigret", "alice", top=5)
        with Hops() as hops:
            with self.assertRaises((TypeError, errors.UsageError)):
                self.case.run(plan)
            for confirm in (None, "", "run", "YES"):
                with self.subTest(confirm=confirm):
                    with self.assertRaises(errors.UsageError):
                        self.case.run(plan, confirm)
        self.assertEqual(hops.calls, [])
        self.assertEqual(self.case.jobs(), [])

    def test_confirmed_run_round_trips_through_jobs(self):
        plan = self.case.plan("maigret", "alice", top=5)
        with Hops():
            result = self.case.run(plan, "RUN")
        self.assertEqual((result["state"], result["exit_code"]), ("complete", 0))
        self.assertEqual([job["id"] for job in self.case.jobs()], [result["job_id"]])
        self.assertEqual(self.case.job_detail(result["job_id"])["result"]["tool_id"], "maigret")

    def test_run_without_authorization_raises_the_typed_error(self):
        self.store.create_case("bare", "No attestation")
        bare = api.open_case("bare", store=self.store)
        plan = bare.plan("maigret", "alice", top=5)
        with Hops() as hops:
            with self.assertRaises(AuthorizationRequired):
                bare.run(plan, "RUN")
        self.assertEqual(hops.calls, [])


class Chains(ApiCase):
    def setUp(self):
        super().setUp()
        authorize_case(self.store, "c")

    def test_dry_run_plans_and_never_executes(self):
        with Hops() as hops:
            result = self.case.chain(spec_of(step("s1", "maigret", "alice", options={"top": 5})), dry_run=True, confirm="RUN")
        self.assertEqual((result["executed"], hops.calls), (False, []))

    def test_confirmed_chain_runs(self):
        with Hops():
            result = self.case.chain(spec_of(step("s1", "maigret", "alice", options={"top": 5})), confirm="RUN")
        self.assertEqual((result["executed"], result["status"]), (True, "complete"))

    def test_spec_for_another_case_and_bad_confirm_are_rejected(self):
        with self.assertRaises(ChainError):
            self.case.chain(spec_of(step("s1", "maigret", "alice"), case_id="other"))
        with self.assertRaises(errors.UsageError):
            self.case.chain(spec_of(step("s1", "maigret", "alice")), confirm="yes")


class ConfigureAndErrors(unittest.TestCase):
    def test_configure_sets_the_toolkit_root_seam(self):
        with patch.dict(os.environ):
            api.configure(toolkit_root=TOOLKIT)
            self.assertEqual(Path(os.environ["OSINT_TOOLKIT_ROOT"]), TOOLKIT)
            self.assertIn("maigret", [entry["id"] for entry in api.catalog()["tools"]])

    def test_catalog_failure_is_a_config_error(self):
        with tempfile.TemporaryDirectory() as empty, patch.dict(os.environ, {"OSINT_TOOLKIT_ROOT": empty}):
            with self.assertRaises(errors.ConfigProviderError):
                api.catalog()

    def test_every_typed_exception_maps_into_the_table(self):
        for cls in (errors.UsageError, errors.NotFoundError, errors.NetworkGateError, errors.ConfigProviderError, errors.InterruptedRun, api.WaitTimeout):
            self.assertIn(cls.code, errors.EXIT_CODES)
        self.assertEqual(errors.exit_code_for(errors.NetworkGateError.code), 75)


if __name__ == "__main__":
    unittest.main()
