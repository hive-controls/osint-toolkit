import contextlib
import copy
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from osint_profiler import catalog, chainstate, cli
from osint_profiler.authorization import AuthorizationRequired, revoke_authorization
from osint_profiler.chainrefs import ChainError
from osint_profiler.chains import plan_chain, run_chain
from osint_profiler.store import Store
from osint_profiler.util import database
from authz_support import authorize_case, legacy_json

REF_FIRST_USERNAME = "${steps.s1.entities[kind=username].value|first}"
SCANNER_OUTPUT = "SCANNER_OUTPUT"


def maigret_report(username, aliases=("alias_one",)):
    return {"GitHub": {"url_user": f"https://github.test/{username}", "ids_usernames": {alias: "username" for alias in aliases},
                       "status": {"status": "Claimed", "username": username, "site_name": "GitHub"}}}


def scanner_report(username):
    return [{"username": username, "site_name": "Example", "status": "Found", "url": f"https://example.test/{username}"}]


def default_script(call):
    if call["tool"] == "maigret":
        return {"code": 0, "name": "report.json", "payload": maigret_report(call["target"])}
    return {"code": 0, "name": "results.json", "payload": scanner_report(call["target"])}


class Hops:
    """Replaces the pwsh/docker boundary: runs script(call) per hop, writing fixture output and returning its exit code."""
    def __init__(self, script=default_script, on_call=None):
        self.script, self.on_call, self.calls = script, on_call, []

    def __enter__(self):
        owner = self

        class Process:
            pid = 4242
            def __init__(self, command, **kwargs):
                plan = json.loads(Path(command[command.index("-PlanFile") + 1]).read_text(encoding="utf-8"))
                call = {"tool": plan["tool"], "target": plan["target"], "env": dict(kwargs["env"]), "index": len(owner.calls)}
                owner.calls.append(call)
                self.outcome = owner.script(call)
                if owner.on_call:
                    owner.on_call(call)
                if self.outcome.get("name"):
                    folder = Path(command[command.index("-PlanFile") + 1]).parent / "output"
                    (folder / self.outcome["name"]).write_text(json.dumps(self.outcome["payload"]), encoding="utf-8")
            def wait(self, **kwargs): return self.outcome["code"]
            def poll(self): return self.outcome["code"]

        self.patches = [patch("osint_profiler.scans.shutil.which", return_value="stub"),
                        patch("osint_profiler.scans.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")),
                        patch("osint_profiler.scans.subprocess.Popen", Process)]
        for item in self.patches:
            item.start()
        return self

    def __exit__(self, *exc):
        for item in self.patches:
            item.stop()


def step(step_id, tool, target, **extra):
    return {"id": step_id, "tool": tool, "inputs": {"target": target}, **extra}


def spec_of(*steps, chain_id="c1", case_id="c"):
    return {"version": 1, "id": chain_id, "case_id": case_id, "steps": list(steps)}


def derived_pair(**second):
    return spec_of(step("s1", "maigret", "alice", options={"top": 5}), step("s2", "user-scanner", REF_FIRST_USERNAME, **second))


class ChainCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(self.directory.name)
        self.store.create_case("c", "Synthetic chain case")
        authorize_case(self.store, "c")
        self.catalog = catalog.load_catalog()
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("OSINT_SUBJECT_AUTH", None)

    def run_it(self, spec, hops=None, **kwargs):
        with (hops or Hops()):
            return run_chain(self.store, spec, self.catalog, kwargs.pop("confirm", "RUN"), **kwargs)

    def events(self, action="chain_step"):
        with database(self.store.db_path("c")) as con:
            rows = con.execute("SELECT * FROM events WHERE action=? ORDER BY rowid", (action,)).fetchall()
        return [json.loads(row["after_json"]) for row in rows]

    def state(self, chain_id="c1"):
        return chainstate.read_state(self.store.case_dir("c"), chain_id)

    def add_case_entities(self):
        self.store.add_entity("c", "known@example.test", "email", "", "known@example.test")
        with database(self.store.db_path("c")) as con:
            self.store._entity(con, "email", "site", "reported@example.test", "reported@example.test", "scanner_reported")


class DryRunPlan(ChainCase):
    def test_literal_input_is_fully_resolved_with_argv_and_user_provenance(self):
        plan = plan_chain(self.store, spec_of(step("s1", "maigret", "alice", options={"top": 7})), self.catalog)
        first = plan["steps"][0]
        self.assertEqual(first["inputs"][0]["provenance"], "user")
        self.assertTrue(first["inputs"][0]["resolved"])
        self.assertIn("7", first["plan"]["arguments"])
        self.assertEqual(plan["chain_id"], "c1")

    def test_later_step_input_stays_unresolved_with_reference_and_expected_kind(self):
        plan = plan_chain(self.store, derived_pair(), self.catalog)
        deferred = plan["steps"][1]["inputs"][0]
        self.assertFalse(deferred["resolved"])
        self.assertEqual(deferred["reference"], REF_FIRST_USERNAME)
        self.assertEqual(deferred["expected_kinds"], ["username"])
        self.assertIsNone(plan["steps"][1]["plan"])

    def test_case_references_resolve_now_and_derived_values_are_listed(self):
        self.add_case_entities()
        spec = spec_of(step("s1", "user-scanner", "${case.entities[kind=email].attrs.label|first}"))
        plan = plan_chain(self.store, spec, self.catalog)
        self.assertEqual(plan["steps"][0]["inputs"][0]["value"], "known@example.test")
        self.assertEqual(plan["steps"][0]["inputs"][0]["provenance"], "user")
        first = spec_of(step("s1", "user-scanner", "${case.entities[kind=email].value|first}", derived_ok=True))
        self.assertEqual(plan_chain(self.store, first, self.catalog)["derived_values"], [])

    def test_derived_case_entity_is_listed_in_dry_run(self):
        with database(self.store.db_path("c")) as con:
            self.store._entity(con, "email", "site", "reported@example.test", "reported@example.test", "scanner_reported")
        spec = spec_of(step("s1", "user-scanner", "${case.entities[kind=email].value|only}", derived_ok=True))
        plan = plan_chain(self.store, spec, self.catalog)
        self.assertEqual([(v["step"], v["value"], v["provenance"]) for v in plan["derived_values"]], [("s1", "reported@example.test", "derived")])
        self.assertEqual(plan["steps"][0]["plan"]["kind"], "email")

    def test_gate_set_is_the_union_of_step_requirements(self):
        altered = copy.deepcopy(self.catalog)
        next(tool for tool in altered["tools"] if tool["id"] == "user-scanner")["gates"]["network"] = "tor"
        plan = plan_chain(self.store, derived_pair(), altered)
        self.assertEqual(plan["gate"]["network"], ["tor", "vpn"])
        self.assertEqual(plan["gate"]["authorization"], "required")

    def test_dry_run_states_that_the_network_is_not_probed(self):
        plan = plan_chain(self.store, derived_pair(), self.catalog)
        self.assertIn("not probed", plan["network"])
        self.assertIn("per hop", plan["network"])

    def test_planning_never_launches_or_writes_state(self):
        with Hops() as hops:
            run_chain(self.store, derived_pair(), self.catalog, None)
        self.assertEqual(hops.calls, [])
        self.assertFalse((self.store.case_dir("c") / "chains").exists())


class StaticChecks(ChainCase):
    def rejects(self, spec, code="spec-invalid"):
        with self.assertRaises(ChainError) as raised:
            plan_chain(self.store, spec, self.catalog)
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_interactive_only_tool_is_rejected_at_plan_time(self):
        error = self.rejects(spec_of(step("s1", "torbot", "x")), "tool-not-chainable")
        self.assertIn("interactive", str(error))

    def test_non_runnable_and_unknown_tools_are_rejected(self):
        self.rejects(spec_of(step("s1", "osint-case", "x")), "tool-not-chainable")
        self.rejects(spec_of(step("s1", "nope", "x")), "tool-not-chainable")

    def test_duplicate_step_ids(self):
        self.rejects(spec_of(step("s1", "maigret", "a"), step("s1", "maigret", "b")))

    def test_forward_self_and_unknown_references(self):
        later = "${steps.s2.entities[kind=username].value|first}"
        self.rejects(spec_of(step("s1", "maigret", later), step("s2", "maigret", "a")))
        self.rejects(spec_of(step("s1", "maigret", "${steps.s1.entities[kind=username].value|first}")))
        self.rejects(spec_of(step("s1", "maigret", "${steps.ghost.entities[kind=username].value|first}")))

    def test_filter_kind_the_tool_cannot_accept(self):
        self.rejects(spec_of(step("s1", "maigret", "a"), step("s2", "user-scanner", "${steps.s1.entities[kind=account].value|first}")), "input-kind-mismatch")

    def test_option_validation_uses_the_catalog(self):
        self.rejects(spec_of(step("s1", "maigret", "a", options={"top": 0})))
        self.rejects(spec_of(step("s1", "maigret", "a", options={"top": "5"})))
        self.rejects(spec_of(step("s1", "maigret", "a", options={"unknown": 1})))
        self.rejects(spec_of(step("s1", "user-scanner", "a", options={"modules": "a b"})))

    def test_input_names_follow_the_catalog(self):
        self.rejects(spec_of({"id": "s1", "tool": "maigret", "inputs": {"who": "a"}}))
        self.rejects(spec_of({"id": "s1", "tool": "maigret", "inputs": {}}))

    def test_literal_that_fails_the_catalog_validator(self):
        self.rejects(spec_of(step("s1", "maigret", "has space")))
        self.rejects(spec_of(step("s1", "maigret", "-flag")))

    def test_schema_violations_are_spec_invalid(self):
        self.rejects({"version": 1, "id": "c1", "case_id": "c", "steps": []})

    def test_ambiguous_case_reference_fails_at_plan_time(self):
        self.store.add_entity("c", "one@example.test", "email", "", "one@example.test")
        self.store.add_entity("c", "two@example.test", "email", "", "two@example.test")
        self.rejects(spec_of(step("s1", "user-scanner", "${case.entities[kind=email].value}")), "ambiguous-input")


class DerivedPolicy(ChainCase):
    def test_derived_input_is_refused_without_derived_ok(self):
        with Hops() as hops:
            result = run_chain(self.store, derived_pair(), self.catalog, "RUN")
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["error"]["error"], "derived-input-refused")
        self.assertEqual(len(hops.calls), 1)
        self.assertEqual([s["action"] for s in result["steps"]], ["ran", "refused"])

    def test_derived_input_is_allowed_with_derived_ok(self):
        with Hops() as hops:
            result = run_chain(self.store, derived_pair(derived_ok=True), self.catalog, "RUN")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual([call["target"] for call in hops.calls], ["alice", "alias_one"])

    def test_statically_known_derived_input_is_refused_before_hop_one(self):
        with database(self.store.db_path("c")) as con:
            self.store._entity(con, "email", "site", "reported@example.test", "reported@example.test", "scanner_reported")
        spec = spec_of(step("s0", "maigret", "alice"), step("s1", "user-scanner", "${case.entities[kind=email].value|only}"))
        with Hops() as hops, self.assertRaises(ChainError) as raised:
            run_chain(self.store, spec, self.catalog, "RUN")
        self.assertEqual(raised.exception.code, "derived-input-refused")
        self.assertEqual(hops.calls, [])

    def test_refusal_is_not_swallowed_by_continue(self):
        spec = spec_of(step("s1", "maigret", "alice", on_error="continue"), step("s2", "user-scanner", REF_FIRST_USERNAME, on_error="continue"),
                       step("s3", "user-scanner", "literal"))
        with Hops() as hops:
            result = run_chain(self.store, spec, self.catalog, "RUN")
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(len(hops.calls), 1)

    def test_derived_provenance_reaches_result_json_and_the_ledger(self):
        result = self.run_it(derived_pair(derived_ok=True))
        envelope = json.loads((Path(result["steps"][1]["folder"]) / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(envelope["inputs"], [{"name": "target", "kind": "username", "value": "alias_one", "provenance": "derived", "from": REF_FIRST_USERNAME}])
        first, second = self.events()
        self.assertEqual(first["provenance"], [{"name": "target", "kind": "username", "provenance": "user", "from": None}])
        self.assertEqual(second["provenance"], [{"name": "target", "kind": "username", "provenance": "derived", "from": REF_FIRST_USERNAME}])

    def test_derived_status_does_not_launder_through_steps_inputs(self):
        spec = spec_of(step("s1", "maigret", "alice"), step("s2", "user-scanner", REF_FIRST_USERNAME, derived_ok=True),
                       step("s3", "user-scanner", "${steps.s2.inputs[kind=username].value|only}"))
        result = self.run_it(spec)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["error"]["error"], "derived-input-refused")


class Ambiguity(ChainCase):
    def test_only_with_many_candidates_is_ambiguous(self):
        spec = spec_of(step("s1", "maigret", "alice"), step("s2", "user-scanner", "${steps.s1.entities[kind=username].value|only}", derived_ok=True))
        result = self.run_it(spec)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["error"]["error"], "ambiguous-input")
        self.assertIn("alias_one", result["error"]["message"])

    def test_scalar_input_without_pipe_is_ambiguous(self):
        spec = spec_of(step("s1", "maigret", "alice"), step("s2", "user-scanner", "${steps.s1.entities[kind=username].value}", derived_ok=True))
        self.assertEqual(self.run_it(spec)["error"]["error"], "ambiguous-input")

    def test_reference_to_an_empty_selection(self):
        spec = spec_of(step("s1", "maigret", "alice"), step("s2", "user-scanner", "${steps.s1.entities[kind=email].value|first}", derived_ok=True))
        self.assertEqual(self.run_it(spec)["error"]["error"], "empty-reference")


class Resume(ChainCase):
    def three_steps(self, **overrides):
        return spec_of(step("s1", "maigret", "alice"), step("s2", "user-scanner", "second", **overrides), step("s3", "user-scanner", "third"))

    def failing_second(self, call):
        return {"code": 1 if call["target"] == "second" else 0, "name": "results.json", "payload": scanner_report(call["target"])} \
            if call["tool"] == "scanner" else default_script(call)

    def test_resume_skips_completed_steps_and_finishes_the_rest(self):
        spec = self.three_steps()
        first = self.run_it(spec, Hops(self.failing_second))
        self.assertEqual((first["exit_code"], [s["action"] for s in first["steps"]]), (1, ["ran", "failed", "pending"]))
        second_hops = Hops()
        resumed = self.run_it(spec, second_hops, resume="c1")
        self.assertEqual(resumed["exit_code"], 0)
        self.assertEqual([s["action"] for s in resumed["steps"]], ["reused", "ran", "ran"])
        self.assertEqual([call["target"] for call in second_hops.calls], ["second", "third"])

    def test_resume_refuses_changed_inputs_without_force(self):
        spec = self.three_steps()
        self.run_it(spec, Hops(self.failing_second))
        changed = self.three_steps()
        changed["steps"][0]["inputs"]["target"] = "bob"
        with Hops() as hops, self.assertRaises(ChainError) as raised:
            run_chain(self.store, changed, self.catalog, "RUN", resume="c1")
        self.assertEqual(raised.exception.code, "input-changed")
        self.assertEqual(hops.calls, [])
        forced = Hops()
        result = self.run_it(changed, forced, resume="c1", force=True)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual([call["target"] for call in forced.calls], ["bob", "second", "third"])

    def test_resume_reruns_a_crashed_running_step_as_a_new_job(self):
        spec = self.three_steps()
        self.run_it(spec)
        state = self.state()
        crashed = state["steps"][1]
        old_job = crashed["job_id"]
        crashed.update(state="running", result_sha256=None, exit_code=None)
        chainstate.write_state(self.store.case_dir("c"), "c1", state)
        with database(self.store.db_path("c")) as con:
            con.execute("UPDATE jobs SET state='running' WHERE id=?", (old_job,))
        hops = Hops()
        result = self.run_it(spec, hops, resume="c1")
        self.assertEqual([s["action"] for s in result["steps"]], ["reused", "ran", "reused"])
        self.assertEqual([call["target"] for call in hops.calls], ["second"])
        self.assertNotEqual(result["steps"][1]["job_id"], old_job)
        self.assertEqual(result["interrupted_jobs"], [old_job])
        with database(self.store.db_path("c")) as con:
            self.assertEqual(con.execute("SELECT state FROM jobs WHERE id=?", (old_job,)).fetchone()["state"], "interrupted")

    def test_modified_result_file_forces_a_rerun_of_that_step(self):
        spec = self.three_steps()
        done = self.run_it(spec)
        result_path = Path(done["steps"][0]["folder"]) / "result.json"
        result_path.write_text(result_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        hops = Hops()
        resumed = self.run_it(spec, hops, resume="c1")
        self.assertEqual([s["action"] for s in resumed["steps"]], ["ran", "reused", "reused"])
        self.assertEqual([call["target"] for call in hops.calls], ["alice"])

    def test_resume_reruns_authorization_per_hop(self):
        spec = self.three_steps()
        self.run_it(spec, Hops(self.failing_second))
        hops = Hops(on_call=lambda call: revoke_authorization(self.store, "c", "mid-resume") if call["target"] == "second" else None)
        result = self.run_it(spec, hops, resume="c1")
        self.assertEqual(result["exit_code"], 77)
        self.assertEqual([call["target"] for call in hops.calls], ["second"])

    def test_resume_after_revocation_stops_before_any_hop(self):
        spec = self.three_steps()
        self.run_it(spec, Hops(self.failing_second))
        revoke_authorization(self.store, "c", "before resume")
        with Hops() as hops, self.assertRaises(AuthorizationRequired):
            run_chain(self.store, spec, self.catalog, "RUN", resume="c1")
        self.assertEqual(hops.calls, [])

    def test_unknown_resume_id_and_existing_chain(self):
        with self.assertRaises(ChainError) as unknown:
            self.run_it(self.three_steps(), resume="other")
        self.assertEqual(unknown.exception.code, "unknown-chain")
        self.run_it(self.three_steps())
        with self.assertRaises(ChainError) as exists:
            self.run_it(self.three_steps())
        self.assertEqual(exists.exception.code, "chain-exists")


class FailClosed(ChainCase):
    def two_literal(self, **second):
        return spec_of(step("s1", "maigret", "alice", on_error="continue"), step("s2", "user-scanner", "second", on_error="continue", **second))

    def test_revocation_between_hops_stops_with_77_even_with_continue(self):
        hops = Hops(on_call=lambda call: revoke_authorization(self.store, "c", "mid-chain") if call["index"] == 0 else None)
        result = self.run_it(self.two_literal(), hops)
        self.assertEqual(result["exit_code"], 77)
        self.assertEqual(len(hops.calls), 1)
        self.assertEqual(result["error"]["error"], "subject-authorization-required")
        self.assertEqual(self.state()["steps"][1]["state"], "failed")

    def test_gate_codes_always_stop_regardless_of_on_error(self):
        for code in (64, 75, 77, 78, 130):
            with self.subTest(code=code):
                chain_id = f"gate-{code}"
                spec = spec_of(step("s1", "maigret", "alice", on_error="continue"), step("s2", "user-scanner", "second"), chain_id=chain_id)
                hops = Hops(lambda call, code=code: {"code": code if call["index"] == 0 else 0, "name": None})
                result = self.run_it(spec, hops)
                self.assertEqual(result["exit_code"], code)
                self.assertEqual(len(hops.calls), 1)

    def test_other_failures_honour_on_error(self):
        failing = lambda call: {"code": 1 if call["index"] == 0 else 0, "name": None}
        stopped = self.run_it(spec_of(step("s1", "maigret", "alice"), step("s2", "user-scanner", "second"), chain_id="stop"), Hops(failing))
        self.assertEqual((stopped["exit_code"], len(stopped["steps"]), stopped["steps"][1]["action"]), (1, 2, "pending"))
        hops = Hops(failing)
        continued = self.run_it(self.two_literal(), hops)
        self.assertEqual(len(hops.calls), 2)
        self.assertEqual(continued["exit_code"], 1)
        self.assertEqual(continued["status"], "failed")

    def test_chain_exit_is_the_first_failing_hops_code(self):
        codes = {0: 3, 1: 5}
        spec = spec_of(step("s1", "maigret", "alice", on_error="continue"), step("s2", "user-scanner", "second", on_error="continue"))
        result = self.run_it(spec, Hops(lambda call: {"code": codes[call["index"]], "name": None}))
        self.assertEqual(result["exit_code"], 3)

    def test_downstream_of_a_continued_failure_is_skipped_not_run(self):
        spec = spec_of(step("s1", "maigret", "alice", on_error="continue"), step("s2", "user-scanner", REF_FIRST_USERNAME, derived_ok=True))
        hops = Hops(lambda call: {"code": 1, "name": None})
        result = self.run_it(spec, hops)
        self.assertEqual(len(hops.calls), 1)
        self.assertEqual((result["exit_code"], result["steps"][1]["action"]), (1, "skipped"))

    def test_all_steps_complete_exits_zero(self):
        result = self.run_it(self.two_literal())
        self.assertEqual((result["exit_code"], result["status"]), (0, "complete"))

    def test_chain_never_sets_gate_environment(self):
        hops = Hops()
        self.run_it(derived_pair(derived_ok=True), hops)
        self.assertEqual(len(hops.calls), 2)
        for call in hops.calls:
            self.assertNotIn("OSINT_SUBJECT_AUTH", call["env"])
            self.assertEqual({key for key in call["env"] if key.startswith("OSINT_")} - set(os.environ), {"OSINT_CASE_ID", "OSINT_ROOT"})

    def test_missing_authorization_stops_before_hop_one(self):
        self.store.create_case("fresh", "No attestation")
        spec = spec_of(step("s1", "maigret", "alice"), case_id="fresh")
        with Hops() as hops, self.assertRaises(AuthorizationRequired):
            run_chain(self.store, spec, self.catalog, "RUN")
        self.assertEqual(hops.calls, [])


class Ledger(ChainCase):
    def test_chain_step_event_per_hop_with_hashes(self):
        result = self.run_it(derived_pair(derived_ok=True))
        events = self.events()
        self.assertEqual([e["step"] for e in events], ["s1", "s2"])
        for event, summary in zip(events, result["steps"]):
            self.assertEqual((event["chain_id"], event["job_id"], event["exit_code"]), ("c1", summary["job_id"], 0))
            self.assertRegex(event["input_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(event["result_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("alias_one", json.dumps(event))

    def test_state_file_records_every_hop(self):
        self.run_it(derived_pair(derived_ok=True))
        state = self.state()
        self.assertEqual((state["status"], state["exit_code"]), ("complete", 0))
        self.assertEqual([(s["id"], s["state"]) for s in state["steps"]], [("s1", "complete"), ("s2", "complete")])
        self.assertTrue(all(s["input_hash"] and s["job_id"] and s["result_sha256"] for s in state["steps"]))

    def test_input_hash_is_stable_and_input_sensitive(self):
        self.run_it(spec_of(step("s1", "maigret", "alice"), chain_id="a"))
        self.run_it(spec_of(step("s1", "maigret", "alice"), chain_id="b"))
        self.run_it(spec_of(step("s1", "maigret", "alice", options={"top": 9}), chain_id="d"))
        hashes = [self.state(name)["steps"][0]["input_hash"] for name in "abd"]
        self.assertEqual(hashes[0], hashes[1])
        self.assertNotEqual(hashes[0], hashes[2])

    def test_state_is_recorded_running_with_job_id_before_launch(self):
        seen = {}
        def observe(call):
            seen["state"] = self.state()["steps"][0]
        self.run_it(spec_of(step("s1", "maigret", "alice")), Hops(on_call=observe))
        self.assertEqual(seen["state"]["state"], "running")
        self.assertTrue(seen["state"]["job_id"])

    def test_concurrent_run_of_the_same_chain_is_refused(self):
        lock = chainstate.hold_lock(self.store.case_dir("c"), "c1")
        self.addCleanup(lock.close)
        with self.assertRaises(ChainError) as raised:
            self.run_it(spec_of(step("s1", "maigret", "alice")))
        self.assertEqual(raised.exception.code, "chain-busy")


class ChainCli(ChainCase):
    def call(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--root", self.directory.name, *argv])
        return code, out.getvalue(), err.getvalue()

    def spec_file(self, spec):
        path = Path(self.directory.name) / "spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        return str(path)

    def test_without_confirm_prints_the_plan_and_exits_zero(self):
        with Hops() as hops:
            code, out, _ = self.call("chain", "run", self.spec_file(derived_pair()), "--json")
        payload = legacy_json(out)
        self.assertEqual((code, payload["executed"], hops.calls), (0, False, []))
        self.assertIn("plan", payload)

    def test_dry_run_flag_never_executes_even_with_confirm(self):
        with Hops() as hops:
            code, out, _ = self.call("chain", "run", self.spec_file(derived_pair()), "--dry-run", "--confirm", "RUN", "--json")
        self.assertEqual((code, legacy_json(out)["executed"], hops.calls), (0, False, []))

    def test_confirmed_run_exits_zero_and_show_and_list_report_it(self):
        spec_path = self.spec_file(derived_pair(derived_ok=True))
        with Hops():
            code, out, _ = self.call("chain", "run", spec_path, "--confirm", "RUN", "--json")
        self.assertEqual((code, legacy_json(out)["status"]), (0, "complete"))
        code, out, _ = self.call("chain", "show", "c1", "--json")
        self.assertEqual((code, legacy_json(out)["status"]), (0, "complete"))
        code, out, _ = self.call("chain", "list", "--json")
        self.assertEqual([(item["chain_id"], item["case_id"], item["status"]) for item in legacy_json(out)], [("c1", "c", "complete")])

    def test_hop_exit_code_is_the_process_exit_code(self):
        spec_path = self.spec_file(spec_of(step("s1", "maigret", "alice")))
        with Hops(lambda call: {"code": 75, "name": None}):
            code, out, _ = self.call("chain", "run", spec_path, "--confirm", "RUN", "--json")
        self.assertEqual(code, 75)
        self.assertEqual(legacy_json(out)["exit_code"], 75)

    def test_spec_errors_exit_two_with_the_error_shape(self):
        code, out, _ = self.call("chain", "run", self.spec_file(spec_of(step("s1", "torbot", "x"))), "--json")
        self.assertEqual(code, 2)
        payload = legacy_json(out)
        self.assertEqual(set(payload), {"error", "message", "next"})
        self.assertEqual(payload["error"], "tool-not-chainable")

    def test_invalid_json_and_missing_file_exit_two(self):
        bad = Path(self.directory.name) / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.call("chain", "run", str(bad), "--json")[0], 2)
        self.assertEqual(self.call("chain", "run", str(bad.with_name("missing.json")), "--json")[0], 2)

    def test_revoked_authorization_exits_77_with_the_existing_payload_shape(self):
        revoke_authorization(self.store, "c", "test")
        code, out, _ = self.call("chain", "run", self.spec_file(spec_of(step("s1", "maigret", "alice"))), "--confirm", "RUN", "--json")
        self.assertEqual(code, 77)
        self.assertEqual(legacy_json(out)["error"], "subject-authorization-required")

    def test_derived_refusal_exits_two(self):
        with Hops():
            code, out, _ = self.call("chain", "run", self.spec_file(derived_pair()), "--confirm", "RUN", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(legacy_json(out)["error"]["error"], "derived-input-refused")

    def test_resume_through_the_cli(self):
        spec_path = self.spec_file(spec_of(step("s1", "maigret", "alice"), step("s2", "user-scanner", "second")))
        with Hops(lambda call: {"code": 1 if call["tool"] == "scanner" else 0, "name": None}):
            self.assertEqual(self.call("chain", "run", spec_path, "--confirm", "RUN", "--json")[0], 1)
        with Hops():
            code, out, _ = self.call("chain", "run", spec_path, "--resume", "c1", "--confirm", "RUN", "--json")
        self.assertEqual((code, [s["action"] for s in legacy_json(out)["steps"]]), (0, ["reused", "ran"]))

    def test_show_unknown_chain(self):
        code, out, _ = self.call("chain", "show", "nope", "--json")
        self.assertEqual((code, legacy_json(out)["error"]), (2, "unknown-chain"))


if __name__ == "__main__":
    unittest.main()
