"""Durable chain state: chains/<chain-id>/{state.json,spec.json,state.lock} under the case directory."""
from __future__ import annotations
import json
import os
from pathlib import Path
from .chainrefs import ChainError
from .util import json_text, now

STATE_VERSION = 1


def chain_dir(case_dir, chain_id):
    return Path(case_dir) / "chains" / chain_id


def hold_lock(case_dir, chain_id):
    """Non-blocking exclusive OS lock for one chain; the caller closes the returned file to release it."""
    folder = chain_dir(case_dir, chain_id)
    folder.mkdir(parents=True, exist_ok=True)
    lock = open(folder / "state.lock", "a+b")
    try:
        lock.seek(0)
        if os.name == "nt":
            import msvcrt
            if not lock.read(1):
                lock.write(b"0"); lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise ChainError("chain-busy", f"Chain {chain_id} is already running in another process.", "Wait for it to finish, then retry or --resume.") from None
    return lock


def read_state(case_dir, chain_id):
    path = chain_dir(case_dir, chain_id) / "state.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ChainError("state-unreadable", f"Cannot read chain state {path.name}: {exc}", "Inspect the chain folder; do not hand-edit state.json.") from None


def write_state(case_dir, chain_id, state):
    folder = chain_dir(case_dir, chain_id)
    folder.mkdir(parents=True, exist_ok=True)
    state["updated"] = now()
    target = folder / "state.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json_text(state), encoding="utf-8")
    os.replace(temporary, target)


def new_state(spec, spec_sha256):
    return {"schema_version": STATE_VERSION, "chain_id": spec["id"], "case_id": spec["case_id"], "status": "running", "exit_code": None,
            "spec_sha256": spec_sha256, "created": now(), "updated": now(),
            "steps": [{"id": item["id"], "state": "pending", "job_id": None, "input_hash": None, "exit_code": None,
                       "result_sha256": None, "inputs": [], "error": None} for item in spec["steps"]]}


def reconcile_steps(state, spec):
    """Resume with a spec whose step list changed: keep records by id, add pending ones, drop removed ones."""
    known = {record["id"]: record for record in state["steps"]}
    fresh = new_state(spec, state["spec_sha256"])["steps"]
    state["steps"] = [known.get(record["id"], record) for record in fresh]


def step_record(state, step_id):
    return next(record for record in state["steps"] if record["id"] == step_id)


def list_chains(store, case_id=None):
    found = []
    for case_dir in sorted(store.cases.iterdir()):
        if (case_id and case_dir.name != case_id) or not (case_dir / "chains").is_dir():
            continue
        for folder in sorted((case_dir / "chains").iterdir()):
            state = read_state(case_dir, folder.name) if folder.is_dir() else None
            if state:
                found.append(state)
    return found
