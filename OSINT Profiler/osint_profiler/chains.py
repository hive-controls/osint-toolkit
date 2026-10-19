"""Declarative chain executor: static planning, then per-hop execution through the real Scanner (its gates are never bypassed)."""
from __future__ import annotations
from . import catalog, chainstate
from .authorization import AuthorizationRequired, authorization_status
from .chainrefs import ChainError, parse_input, select_one
from .chainsources import base_kind, case_candidates, read_result, step_candidates
from .schemacheck import validate
from .scans import Scanner, plan_scan
from .util import database, digest, json_text, now, uid

ALWAYS_STOP = {64, 75, 77, 78, 130}
NETWORK_NOTE = "not probed; the network gate is enforced per hop by each runner"
OPTION_NAMES = ("top", "region", "modules")


def chainable_entry(loaded, tool):
    entry = catalog.tool(tool, loaded) if isinstance(tool, str) else None
    if entry is None:
        raise ChainError("tool-not-chainable", f"Unknown tool {tool!r}.")
    if entry["interactive_only"]:
        raise ChainError("tool-not-chainable", f"{entry['id']} is interactive-only and cannot be chained.")
    if catalog.internal_id(entry, loaded) not in catalog.scan_tools(loaded):
        raise ChainError("tool-not-chainable", f"{entry['id']} has no non-interactive runner and cannot be chained.")
    return entry


def accepted_kinds(entry):
    return next(item["kind"] for item in entry["inputs"] if item["name"] == "target")


def _literal_kind(entry, value):
    kinds = accepted_kinds(entry)
    if len(kinds) == 1:
        return kinds[0]
    return "email" if "@" in value and "email" in kinds else "username" if "username" in kinds else kinds[0]


def _check_kind(entry, kind, text):
    if base_kind(kind) not in accepted_kinds(entry):
        raise ChainError("input-kind-mismatch", f"{text} yields a {kind!r} value but {entry['id']} accepts {', '.join(accepted_kinds(entry))}.")
    return base_kind(kind)


def _check_input_names(entry, step):
    declared = {item["name"] for item in entry["inputs"]}
    unknown = sorted(set(step["inputs"]) - declared)
    missing = sorted(item["name"] for item in entry["inputs"] if item["required"] and item["name"] not in step["inputs"])
    if unknown or missing:
        raise ChainError("spec-invalid", f"Step {step['id']}: inputs must be {sorted(declared)} (unknown: {unknown}, missing: {missing}).")


def resolve_input(store, case_id, entry, name, text, state=None):
    """A resolved input dict, or None when it references a step whose output does not exist yet (plan time)."""
    reference = parse_input(text)
    if reference is None:
        return {"name": name, "kind": _literal_kind(entry, text), "value": text, "provenance": "user", "from": None}
    if reference.namespace == "case":
        candidates = case_candidates(store, case_id, reference.path)
    elif state is None:
        return None
    else:
        candidates = step_candidates(store, case_id, chainstate.step_record(state, reference.step), reference.path)
    item = select_one(reference, candidates)
    return {"name": name, "kind": _check_kind(entry, item["kind"], reference.text), "value": item["value"],
            "provenance": item["provenance"], "from": reference.text}


def _validate_spec(spec):
    errors = validate(spec, catalog.load_chain_schema())
    if errors:
        raise ChainError("spec-invalid", "Invalid chain spec: " + "; ".join(errors[:5]))
    ids = [item["id"] for item in spec["steps"]]
    if len(set(ids)) != len(ids):
        raise ChainError("spec-invalid", "Step ids must be unique.")


def _check_references(entry, step, earlier):
    for text in step["inputs"].values():
        reference = parse_input(text)
        if reference is None:
            continue
        if reference.namespace == "steps" and reference.step not in earlier:
            raise ChainError("spec-invalid", f"Step {step['id']} references {reference.step!r}, which is not an earlier step.")
        if reference.kind:
            _check_kind(entry, reference.kind, reference.text)


def _expected_kinds(entry, text):
    reference = parse_input(text)
    return [base_kind(reference.kind)] if reference and reference.kind else list(accepted_kinds(entry))


def scan_plan(store, case_id, entry, inputs, options, code):
    target = inputs[0]
    try:
        return plan_scan(store, case_id, entry["id"], target["value"], target["kind"], **options)
    except ChainError:
        raise
    except ValueError as exc:
        raise ChainError(code, f"{entry['id']} rejected {target['value']!r}: {exc}") from None


def _plan_step(store, spec, step, entry, earlier):
    _check_input_names(entry, step)
    _check_references(entry, step, earlier)
    options = step.get("options", {})
    try:
        catalog.validate_options(entry, options)
    except ValueError as exc:
        raise ChainError("spec-invalid", f"Step {step['id']}: {exc}") from None
    rows, resolved = [], []
    for name, text in step["inputs"].items():
        item = resolve_input(store, spec["case_id"], entry, name, text)
        resolved.append(item)
        reference = parse_input(text)
        rows.append({**(item or {"name": name, "kind": None, "value": None, "provenance": None, "from": None}),
                     "reference": reference.text if reference else None, "expected_kinds": _expected_kinds(entry, text), "resolved": item is not None})
    code = "spec-invalid" if all(parse_input(text) is None for text in step["inputs"].values()) else "input-invalid"
    plan = scan_plan(store, spec["case_id"], entry, resolved, options, code) if all(resolved) else None
    return {"id": step["id"], "tool": entry["id"], "tool_version": entry["version"], "options": options, "derived_ok": step.get("derived_ok", False),
            "on_error": step.get("on_error", "stop"), "gates": entry["gates"], "inputs": rows, "plan": plan}


def union_gates(step_gates):
    network = sorted({gate["network"] for gate in step_gates} - {"none"}) or ["none"]
    authorization = sorted({gate["subject_authorization"] for gate in step_gates})
    return {"network": network, "subject_authorization": authorization, "authorization": "required" if "required" in authorization else "none"}


def plan_chain(store, spec, loaded=None):
    loaded = loaded or catalog.load_catalog()
    _validate_spec(spec)
    store.db_path(spec["case_id"])
    steps, earlier = [], set()
    for step in spec["steps"]:
        entry = chainable_entry(loaded, step["tool"])
        steps.append(_plan_step(store, spec, step, entry, earlier))
        earlier.add(step["id"])
    derived = [{"step": item["id"], "name": row["name"], "value": row["value"], "provenance": row["provenance"], "from": row["from"]}
               for item in steps for row in item["inputs"] if row["provenance"] == "derived"]
    return {"chain_id": spec["id"], "case_id": spec["case_id"], "steps": steps, "gate": union_gates([item["gates"] for item in steps]),
            "derived_values": derived, "network": NETWORK_NOTE,
            "authorization": authorization_status(store, spec["case_id"])["status"]}


def enforce_derived(step_id, derived_ok, inputs):
    derived = [row for row in inputs if row["provenance"] == "derived"]
    if derived and not derived_ok:
        listing = ", ".join(f"{row['name']}={row['value']!r} (from {row['from']})" for row in derived)
        raise ChainError("derived-input-refused", f"Step {step_id} would receive derived input(s): {listing}. Derived values are default-deny.")


def input_hash(entry, loaded, options, inputs):
    effective = {item["name"]: options.get(item["name"], item["default"]) for item in entry["options"]}
    return digest(json_text({"tool_id": entry["id"], "tool_version": entry["version"], "catalog_version": loaded["catalog_version"], "options": effective,
                             "inputs": [{"name": row["name"], "kind": row["kind"], "value": row["value"]} for row in inputs]}).encode("utf-8"))


def _open_state(store, spec, resume):
    case_dir = store.case_dir(spec["case_id"])
    existing = chainstate.read_state(case_dir, spec["id"])
    spec_hash = digest(json_text(spec).encode("utf-8"))
    if resume:
        if resume != spec["id"] or existing is None:
            raise ChainError("unknown-chain", f"No chain {resume!r} to resume for this spec in case {spec['case_id']}.", "Run: osint-case chain list --json")
        chainstate.reconcile_steps(existing, spec)
        existing.update(status="running", exit_code=None)
        return existing
    if existing:
        raise ChainError("chain-exists", f"Chain {spec['id']} already has recorded state.", f"Resume it: osint-case chain run <spec> --resume {spec['id']}")
    (chainstate.chain_dir(case_dir, spec["id"]) / "spec.json").write_text(json_text(spec), encoding="utf-8")
    return chainstate.new_state(spec, spec_hash)


def run_chain(store, spec, loaded=None, confirm=None, resume=None, force=False):
    loaded = loaded or catalog.load_catalog()
    plan = plan_chain(store, spec, loaded)
    if confirm != "RUN":
        return {"plan": plan, "executed": False, "next": "Review this plan, then repeat with --confirm RUN."}
    for item in plan["steps"]:
        enforce_derived(item["id"], item["derived_ok"], [row for row in item["inputs"] if row["resolved"]])
    status = authorization_status(store, spec["case_id"])
    if status["status"] != "valid":
        raise AuthorizationRequired(spec["case_id"], status["status"])
    lock = chainstate.hold_lock(store.case_dir(spec["case_id"]), spec["id"])
    try:
        state = _open_state(store, spec, resume)
        return ChainExecutor(store, spec, loaded, state, force).run()
    finally:
        lock.close()


class ChainExecutor:
    def __init__(self, store, spec, loaded, state, force):
        self.store, self.spec, self.loaded, self.state, self.force = store, spec, loaded, state, force
        self.case_id, self.chain_id = spec["case_id"], spec["id"]
        self.case_dir = store.case_dir(self.case_id)
        self.actions, self.interrupted, self.error = {}, [], None

    def save(self):
        chainstate.write_state(self.case_dir, self.chain_id, self.state)

    def run(self):
        first_failure = None
        self.save()
        for step in self.spec["steps"]:
            code, stop = self._advance(step)
            first_failure = first_failure or code
            if code and stop:
                break
        complete = all(record["state"] == "complete" for record in self.state["steps"])
        self.state.update(status="complete" if complete else "failed", exit_code=0 if complete else (first_failure or 1))
        self.save()
        return self._report()

    def _report(self):
        steps = []
        for record in self.state["steps"]:
            folder = self.case_dir / "runs" / record["job_id"] if record["job_id"] else None
            steps.append({"id": record["id"], "action": self.actions.get(record["id"], "pending"), "state": record["state"], "job_id": record["job_id"],
                          "exit_code": record["exit_code"], "folder": str(folder) if folder else None})
        report = {"chain_id": self.chain_id, "case_id": self.case_id, "executed": True, "status": self.state["status"], "exit_code": self.state["exit_code"],
                  "steps": steps, "interrupted_jobs": self.interrupted, "state_file": str(chainstate.chain_dir(self.case_dir, self.chain_id) / "state.json")}
        if self.error:
            report["error"] = self.error
        return report

    def _advance(self, step):
        record = chainstate.step_record(self.state, step["id"])
        entry = chainable_entry(self.loaded, step["tool"])
        try:
            inputs = [resolve_input(self.store, self.case_id, entry, name, text, self.state) for name, text in step["inputs"].items()]
            enforce_derived(step["id"], step.get("derived_ok", False), inputs)
            options = step.get("options", {})
            digest_value = input_hash(entry, self.loaded, options, inputs)
            if self._reusable(record, digest_value):
                self.actions[step["id"]] = "reused"
                return 0, False
            plan = scan_plan(self.store, self.case_id, entry, inputs, options, "input-invalid")
        except ChainError as exc:
            if exc.code == "input-changed":
                raise
            return self._refuse(step, record, exc)
        return self._launch(step, record, plan, inputs, digest_value)

    def _reusable(self, record, digest_value):
        if record["state"] in ("pending", "refused", "skipped") or record["input_hash"] is None:
            return False
        if record["input_hash"] != digest_value:
            if not self.force:
                raise ChainError("input-changed", f"Step {record['id']}: resolved inputs differ from the recorded run.", "Review the change, then repeat with --force to re-run it.")
            return False
        if record["state"] != "complete":
            return False
        _, sha = read_result(self.case_dir / "runs" / record["job_id"])
        return sha is not None and sha == record["result_sha256"]

    def _refuse(self, step, record, exc):
        if exc.code == "upstream-failed":
            record.update(state="skipped", error=exc.payload())
            self.actions[step["id"]] = "skipped"
            self.save()
            return 0, False
        record.update(state="refused", error=exc.payload())
        self.actions[step["id"]] = "refused"
        self.error = self.error or exc.payload()
        self.save()
        return 2, True

    def _mark_interrupted(self, job_id):
        with database(self.store.db_path(self.case_id)) as con:
            changed = con.execute("UPDATE jobs SET state='interrupted',ended=?,message=? WHERE id=? AND state='running'",
                                  (now(), "Chain resume found this hop unfinished; it was re-run as a new job.", job_id)).rowcount
        if changed:
            self.interrupted.append(job_id)

    def _launch(self, step, record, plan, inputs, digest_value):
        if record["state"] == "running" and record["job_id"]:
            self._mark_interrupted(record["job_id"])
        job_id = uid()
        record.update(state="running", job_id=job_id, input_hash=digest_value, exit_code=None, result_sha256=None, inputs=inputs, error=None)
        self.save()
        code, sha, error = self._hop(plan, job_id, inputs[0])
        record.update(state="complete" if code == 0 else "failed", exit_code=code, result_sha256=sha, error=error)
        self.actions[step["id"]] = "ran" if code == 0 else "failed"
        if error and not self.error:
            self.error = error
        self.save()
        self._ledger(step["id"], job_id, digest_value, code, sha, inputs)
        return code, code in ALWAYS_STOP or step.get("on_error", "stop") == "stop"

    def _hop(self, plan, job_id, target):
        origin = {"provenance": target["provenance"], "from": target["from"]}
        try:
            started = Scanner(self.store).start(plan, job_id=job_id, input_origin=origin)
        except AuthorizationRequired as exc:
            return 77, None, exc.payload()
        except ValueError as exc:
            return 1, None, {"error": "hop-failed", "message": str(exc), "next": "Fix the cause, then repeat with --resume."}
        envelope, sha = read_result(started["folder"])
        if envelope is None:
            with database(self.store.db_path(self.case_id)) as con:
                row = con.execute("SELECT exit_code FROM jobs WHERE id=?", (job_id,)).fetchone()
            return (row["exit_code"] if row and row["exit_code"] else 1), None, None
        code = envelope["exit_code"] or (1 if envelope["errors"] else 0)
        return code, sha, None

    def _ledger(self, step_id, job_id, digest_value, code, sha, inputs):
        after = {"chain_id": self.chain_id, "step": step_id, "job_id": job_id, "input_hash": digest_value, "exit_code": code, "result_sha256": sha,
                 "provenance": [{"name": row["name"], "kind": row["kind"], "provenance": row["provenance"], "from": row["from"]} for row in inputs]}
        with database(self.store.db_path(self.case_id)) as con:
            self.store.event(con, "chain_step", self.chain_id, after=after)


def show_chain(store, chain_id, case_id=None):
    matches = [state for state in chainstate.list_chains(store, case_id) if state["chain_id"] == chain_id]
    if len(matches) != 1:
        raise ChainError("unknown-chain" if not matches else "ambiguous-chain", f"{'No' if not matches else 'Several'} chain(s) named {chain_id!r}.", "Run: osint-case chain list --json")
    return matches[0]


def list_chain_summaries(store):
    return [{"chain_id": s["chain_id"], "case_id": s["case_id"], "status": s["status"], "exit_code": s["exit_code"], "updated": s["updated"],
             "steps": [{"id": r["id"], "state": r["state"]} for r in s["steps"]]} for s in chainstate.list_chains(store)]
