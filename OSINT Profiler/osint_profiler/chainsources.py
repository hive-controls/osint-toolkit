"""Candidate values a chain reference can select: case-level data and earlier steps' recorded results."""
from __future__ import annotations
import json
from pathlib import Path
from .chainrefs import ChainError
from .util import database, digest


def base_kind(kind):
    return str(kind).split(".")[0]


def candidate(kind, value, attrs, provenance, origin=None):
    return {"kind": kind, "value": str(value), "attrs": attrs, "provenance": provenance, "from": origin}


def read_result(run_folder):
    """(envelope, sha256 of the exact bytes) or (None, None) when result.json is missing or unreadable."""
    path = Path(run_folder) / "result.json"
    try:
        data = path.read_bytes()
        return json.loads(data.decode("utf-8")), digest(data)
    except (OSError, ValueError):
        return None, None


def _case_entities(store, case_id):
    # No review-accepted flag exists on entities, so every case entity is eligible; provenance is user only for user_declared ones.
    with database(store.db_path(case_id)) as con:
        rows = con.execute("SELECT * FROM entities ORDER BY rowid").fetchall()
    return [candidate(row["kind"], row["identifier"], {"id": row["id"], "platform": row["platform"], "label": row["label"], "basis": row["basis"]},
                      "user" if row["basis"] == "user_declared" else "derived") for row in rows]


def _case_inputs(store, case_id):
    seen, found = set(), []
    for result_path in sorted((store.case_dir(case_id) / "runs").glob("*/result.json")):
        envelope, _ = read_result(result_path.parent)
        for item in (envelope or {}).get("inputs", []):
            key = (item["kind"], item["value"])
            if item["provenance"] == "user" and key not in seen:
                seen.add(key)
                found.append(candidate(item["kind"], item["value"], {"name": item["name"], "tool_id": envelope["tool_id"], "job_id": envelope["job_id"]}, "user"))
    return found


def _case_artifacts(store, case_id):
    with database(store.db_path(case_id)) as con:
        rows = con.execute("SELECT * FROM artifacts ORDER BY rowid").fetchall()
    return [candidate(row["adapter"], row["path"], {"id": row["id"], "name": row["name"], "sha256": row["sha256"]}, "user") for row in rows]


def case_candidates(store, case_id, path):
    return {"entities": _case_entities, "inputs": _case_inputs, "artifacts": _case_artifacts}[path](store, case_id)


def verified_result(store, case_id, record):
    folder = store.case_dir(case_id) / "runs" / str(record["job_id"])
    envelope, sha = read_result(folder)
    if envelope is None or sha != record["result_sha256"]:
        raise ChainError("result-changed", f"Result of step {record['id']} no longer matches its recorded hash.", "Re-run that step with --resume, or use --force after reviewing the change.")
    return envelope


def step_candidates(store, case_id, record, path):
    if record["state"] != "complete":
        raise ChainError("upstream-failed", f"Step {record['id']} did not complete; its outputs cannot be referenced.")
    if path == "inputs":
        return [candidate(item["kind"], item["value"], {"name": item["name"], "from": item["from"]}, item["provenance"]) for item in record["inputs"]]
    envelope = verified_result(store, case_id, record)
    if path == "entities":
        return [candidate(e["kind"], e["value"], e["attrs"], "user" if e["provenance"] == "user" else "derived") for e in envelope["entities"]]
    return [candidate(a["kind"], a["path"], {"sha256": a["sha256"], "bytes": a["bytes"], "adapter": a["adapter"]}, "derived") for a in envelope["artifacts"]]
