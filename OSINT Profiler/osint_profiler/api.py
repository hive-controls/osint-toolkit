"""Library API: plain dicts in and out, typed exceptions (see errors.py), never prints and never prompts."""
from __future__ import annotations
import os
import time
from pathlib import Path
from . import catalog as catalog_module
from . import chains, scans
from .authorization import REQUIRED_PHRASE, authorization_status, current_authorization, record_authorization
from .chainrefs import ChainError
from .chainsources import read_result
from .errors import ConfigProviderError, NotFoundError, ProfilerError, UsageError
from .store import Store


class WaitTimeout(ProfilerError):
    code = "timeout"


def configure(toolkit_root=None):
    """Point an installed copy at a toolkit checkout (runners, catalog). Process-wide, like OSINT_TOOLKIT_ROOT."""
    if toolkit_root is not None:
        os.environ["OSINT_TOOLKIT_ROOT"] = str(Path(toolkit_root).resolve())
        scans.reset_tool_cache()


def catalog():
    try:
        return catalog_module.load_catalog()
    except catalog_module.CatalogError as exc:
        raise ConfigProviderError(str(exc)) from None


def run_chain_spec(store, spec, dry_run=False, resume=None, force=False, confirm=None):
    if confirm not in (None, "RUN"):
        raise UsageError('confirm must be "RUN" or omitted.')
    return chains.run_chain(store, spec, None, None if dry_run else confirm, resume, force)


def open_case(case_id, root=None, store=None):
    return Case(store or Store(root), case_id)


class Case:
    def __init__(self, store, case_id):
        self.store, self.case_id = store, case_id
        try:
            store.db_path(case_id)
        except ValueError as exc:
            raise NotFoundError(str(exc)) from None

    def summary(self):
        return self.store.summary(self.case_id)

    def authorization(self):
        status = authorization_status(self.store, self.case_id)
        record = current_authorization(self.store, self.case_id) or {}
        detail = {key: record.get(key) for key in ("subject_label", "purpose", "legal_basis", "jurisdiction", "operator", "ts", "revoked_ts", "revoke_reason")}
        return {"case_id": self.case_id, "status": status["status"], "attestation_id": status["attestation_id"], "expires_ts": status["expires_ts"], **detail}

    def authorize(self, subject_label, purpose, legal_basis, jurisdiction, acknowledgement, purpose_note="", basis_note=""):
        if acknowledgement != REQUIRED_PHRASE:
            raise UsageError("The acknowledgement phrase must be typed exactly as shown in ACKNOWLEDGEMENT.txt. Nothing was recorded.", f"Pass acknowledgement={REQUIRED_PHRASE!r}.")
        try:
            record = record_authorization(self.store, self.case_id, subject_label, purpose, legal_basis, jurisdiction, acknowledgement, purpose_note, basis_note)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        return {"case_id": self.case_id, "attestation_id": record["id"], "subject_label": record["subject_label"], "expires_ts": record["expires_ts"]}

    def plan(self, tool, target, kind="username", top=500, region="", modules=""):
        try:
            plan = scans.plan_scan(self.store, self.case_id, tool, target, kind, top, region, modules)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        entry = catalog_module.tool(plan["tool"])
        return {**plan, "gates": entry["gates"], "confirm_required": "RUN"}

    def run(self, plan, confirm, background=False):
        if confirm != "RUN":
            raise UsageError('Running a scan requires confirm="RUN".', "Review the plan, then call run(plan, confirm=\"RUN\").")
        started = scans.Scanner(self.store).start(plan, background=background)
        if background:
            return {**started, "state": "running", "exit_code": None}
        job = self.job(started["job_id"])
        return {**started, "state": job["state"], "exit_code": job["exit_code"], "message": job["message"]}

    def chain(self, spec, dry_run=False, resume=None, force=False, confirm=None):
        if not isinstance(spec, dict) or spec.get("case_id") != self.case_id:
            raise ChainError("spec-invalid", "The chain spec's case_id must match this case.")
        return run_chain_spec(self.store, spec, dry_run, resume, force, confirm)

    def jobs(self):
        return self.summary()["jobs"]

    def job(self, job_id):
        found = next((job for job in self.jobs() if job["id"] == job_id), None)
        if found is None:
            raise NotFoundError(f"Job {job_id} not found in case {self.case_id}.", f"Run: osint-case job list {self.case_id} --json")
        return found

    def job_detail(self, job_id):
        job = self.job(job_id)
        result, _ = read_result(self.store.resolve_run_path(self.case_id, job["path"]))
        return {**job, "result": result}

    def cancel_job(self, job_id):
        self.job(job_id)
        try:
            return scans.Scanner(self.store).cancel(job_id)
        except ValueError as exc:
            raise ProfilerError(str(exc), "Cancel from the process that started the job, or wait for it to finish.") from None

    def wait_job(self, job_id, timeout=None, poll_seconds=0.2):
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            job = self.job(job_id)
            if job["state"] != "running":
                return job
            if deadline is not None and time.monotonic() >= deadline:
                raise WaitTimeout(f"Job {job_id} is still running.", f"Run: osint-case job wait {self.case_id} {job_id} --timeout <seconds>")
            time.sleep(poll_seconds)

    def review_observation(self, fingerprint, verdict, reason=""):
        return self._edit(self.store.review_observation, fingerprint, verdict, reason)

    def update(self, title=None, question=None, status=None):
        if title is None and question is None and status is None:
            raise UsageError("Give at least one of title, question or status.")
        return self._edit(self.store.update_case, title, question, status)

    def remove_evidence(self, evidence_id):
        return self._edit(self.store.remove_evidence, evidence_id)

    def undo(self, event_id):
        return self._edit(self.store.undo, event_id)

    def relations(self):
        return self.summary()["relations"]

    def _edit(self, method, *values):
        try:
            return method(self.case_id, *values)
        except ProfilerError:
            raise
        except ValueError as exc:
            raise (NotFoundError if "not found" in str(exc).lower() else UsageError)(str(exc)) from None
