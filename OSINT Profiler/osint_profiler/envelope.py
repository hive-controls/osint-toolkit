"""Typed result envelope: runs/<job>/result.json, written after every run and validated against result.schema.json."""
from __future__ import annotations
import hashlib
import re
from collections import Counter
from pathlib import Path
from . import adapters, catalog
from .schemacheck import validate
from .util import MAX_FILE, digest, json_text

SCHEMA_VERSION = 1
ERROR_CODES = {75: "network_gate_refused", 77: "authorization_required", 78: "network_gate_configuration", 130: "cancelled"}
PHONE_META_KEYS = ("valid", "line_type", "region", "location", "carrier_prefix")
RUN_ADAPTERS = ("maigret", "scanner", "phone")


def _glob_regex(glob):
    pattern = re.escape(glob).replace(r"\*\*/", "(?:.*/)?").replace(r"\*", "[^/]*")
    return re.compile(pattern + r"\Z")


def _artifact_kind(entry, relative):
    for output in entry["outputs"]:
        if _glob_regex(output["glob"]).match(relative):
            return output["kind"]
    return "file"


def _file_digest(path, size):
    if size <= MAX_FILE:
        data = path.read_bytes()
        return digest(data), data
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest(), None


def collect_artifacts(run_folder, entry):
    """Hash every file under output/. Returns (artifact records, [(sha256, adapter inspection)])."""
    artifacts, inspections = [], []
    for path in sorted((Path(run_folder) / "output").rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(run_folder).as_posix()
        size = path.stat().st_size
        sha, data = _file_digest(path, size)
        inspection = adapters.inspect(data, path.name) if data is not None else None
        adapter = inspection["adapter"] if inspection and inspection["adapter"] in RUN_ADAPTERS else None
        if adapter:
            inspections.append((sha, inspection))
        artifacts.append({"kind": _artifact_kind(entry, relative), "path": relative, "sha256": sha, "adapter": adapter, "bytes": size})
    return artifacts, inspections


def _entity(kind, value, attrs, provenance, sha, selector=None, reported_status=None):
    identity = "\0".join([kind, str(value), str(selector), str(sha), provenance])
    return {"id": digest(identity.encode("utf-8"))[:16], "kind": kind, "value": str(value), "attrs": attrs, "provenance": provenance,
            "source_artifact_sha256": sha, "selector": selector, "reported_status": reported_status, "identity_assertion": False}


def _derived_usernames(extra):
    found = extra.get("ids_usernames") or []
    names = list(found) if isinstance(found, (dict, list)) else [found]
    return [str(name) for name in names if name]


def _account_entities(sha, observations):
    entities, counts = [], {}
    for obs in observations:
        counts.setdefault((obs["query"], obs["identifier_kind"]), Counter())[obs["status"]] += 1
        if obs["status"] != "hit":
            continue
        if obs["url"]:
            attrs = {"site": obs["site"], "query": obs["query"], "status": obs["status"], "reported_status": obs["reported_status"]}
            entities.append(_entity("account", obs["url"], attrs, "reported", sha, obs["selector"], obs["reported_status"]))
        for name in _derived_usernames(obs["extra"]):
            attrs = {"site": obs["site"], "derived_from": obs["query"]}
            entities.append(_entity("username", name, attrs, "derived", sha, obs["selector"], obs["reported_status"]))
    for (query, kind), tally in counts.items():
        entities.append(_entity(kind, query, {"counts": dict(tally)}, "user", None))
    return entities


def _phone_entities(sha, observations):
    entities = []
    for obs in observations:
        if obs["site"] == "numbering-plan":
            entities.append(_entity("phone.e164", obs["query"], {}, "user", None))
            attrs = {key: obs["extra"].get(key) for key in PHONE_META_KEYS}
            entities.append(_entity("phone.meta", obs["query"], attrs, "reported", sha, obs["selector"], obs["reported_status"]))
        else:
            attrs = {"source": obs["site"], "state": obs["status"]}
            entities.append(_entity("breach.signal", obs["site"], attrs, "reported", sha, obs["selector"], obs["reported_status"]))
    return entities


def build_entities(inspections):
    entities = {}
    for sha, inspection in inspections:
        build = _phone_entities if inspection["adapter"] == "phone" else _account_entities
        for entity in build(sha, inspection["observations"]):
            entities.setdefault(entity["id"], entity)
    return list(entities.values())


def infer_kind(tool, arguments):
    """Identifier kind for interactive-menu runs, which carry no validated plan."""
    if tool == "phone":
        return "phone"
    return "email" if any(flag in arguments for flag in ("-e", "-ef")) else "username"


def _errors(code, message):
    if not code and not message:
        return []
    error_code = ERROR_CODES.get(code, "tool_failed") if code else "partial"
    return [{"code": error_code, "message": (message or f"Exit code {code}").strip()}]


def _network_gate_code(code):
    return "PASS" if code == 0 else code if code in (75, 78) else None


def build_envelope(plan, job_id, started, finished, code, message, authorization, run_folder, loaded=None):
    loaded = loaded or catalog.load_catalog()
    entry = catalog.tool(plan["tool"], loaded)
    origin = plan.get("input_origin") or {"provenance": "user", "from": None}
    artifacts, inspections = collect_artifacts(run_folder, entry)
    return {"schema_version": SCHEMA_VERSION, "tool_id": entry["id"], "tool_version": entry["version"],
            "catalog_version": loaded["catalog_version"], "case_id": plan["case_id"], "job_id": job_id, "chain": None,
            "started": started, "finished": finished, "exit_code": code,
            "gate": {"network": {"code": _network_gate_code(code), "mode": None}, "authorization": authorization},
            "inputs": [{"name": "target", "kind": plan["kind"], "value": plan["target"], "provenance": origin["provenance"], "from": origin["from"]}],
            "artifacts": artifacts, "entities": build_entities(inspections), "errors": _errors(code, message)}


def write_result(run_folder, envelope):
    errors = validate(envelope, catalog.load_result_schema())
    if errors:
        raise ValueError("Result envelope failed schema validation: " + "; ".join(errors[:3]))
    target = Path(run_folder) / "result.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json_text(envelope), encoding="utf-8")
    temporary.replace(target)
    return target
