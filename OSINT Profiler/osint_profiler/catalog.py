"""Tool catalog: the single declarative source for tool ids, versions, validators and argv."""
from __future__ import annotations
import json
import os
import re
from pathlib import Path, PurePosixPath
from .schemacheck import validate
from .util import toolkit_root as util_toolkit_root

CATALOG_RELATIVE = Path("shared") / "catalog"
PLACEHOLDER = re.compile(r"\{(\w+)\}")


class CatalogError(ValueError):
    pass


def toolkit_root():
    return util_toolkit_root()


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise CatalogError(f"Cannot read {path}: {exc}") from None


def load_catalog(root=None):
    base = Path(root).resolve() if root else toolkit_root()
    data = _read_json(base / CATALOG_RELATIVE / "tools.json")
    schema = _read_json(base / CATALOG_RELATIVE / "schema" / "catalog.schema.json")
    errors = validate(data, schema)
    if errors:
        raise CatalogError("Invalid tool catalog: " + "; ".join(errors[:5]))
    return data


def load_result_schema(root=None):
    base = Path(root).resolve() if root else toolkit_root()
    return _read_json(base / CATALOG_RELATIVE / "schema" / "result.schema.json")


def load_chain_schema(root=None):
    base = Path(root).resolve() if root else toolkit_root()
    return _read_json(base / CATALOG_RELATIVE / "schema" / "chain.schema.json")


def canonical_id(identifier, catalog):
    return catalog["legacy_ids"].get(identifier, identifier)


def internal_id(entry, catalog):
    """The id the runtime (jobs table, runners, adapters) uses: the legacy alias when one exists."""
    return next((legacy for legacy, canonical in catalog["legacy_ids"].items() if canonical == entry["id"]), entry["id"])


def tool(identifier, catalog=None):
    catalog = catalog or load_catalog()
    wanted = canonical_id(str(identifier), catalog)
    return next((entry for entry in catalog["tools"] if entry["id"] == wanted), None)


def scan_tools(catalog=None):
    """Tools the profiler may run non-interactively, keyed by internal id."""
    catalog = catalog or load_catalog()
    result = {}
    for entry in catalog["tools"]:
        if entry["interactive_only"] or not entry["output_env"]:
            continue
        runner = PurePosixPath(entry["runner"])
        result[internal_id(entry, catalog)] = (str(runner.parent), runner.name, entry["output_env"])
    return result


def _check_input(entry, target, kind):
    spec = next(item for item in entry["inputs"] if item["name"] == "target")
    if spec.get("coerce_kind"):
        kind = spec["kind"][0]
    elif kind not in spec["kind"]:
        raise ValueError(spec["kind_error"])
    if "pattern" in spec and not re.fullmatch(spec["pattern"], target):
        raise ValueError(spec["pattern_error"])
    return kind


def _check_option(spec, value):
    if spec["type"] == "integer":
        number = int(value)
        if not spec.get("min", number) <= number <= spec.get("max", number):
            raise ValueError(spec["error"])
    elif value and "pattern" in spec and not re.fullmatch(spec["pattern"], value):
        raise ValueError(spec["error"])


def validate_request(entry, rules, target, kind, options):
    """Thin generic validator: identifier rules, kind restrictions, option bounds/patterns. Returns the effective kind."""
    if not target or len(target) > rules["max_length"] or target.startswith(rules["forbidden_prefix"]) or re.search(rules["forbidden_pattern"], target):
        raise ValueError(rules["target_error"])
    if kind not in rules["kinds"]:
        raise ValueError(rules["kind_error"])
    kind = _check_input(entry, target, kind)
    for spec in entry["options"]:
        _check_option(spec, options.get(spec["name"], spec["default"]))
    return kind


def validate_options(entry, options):
    """Options-only validation (no target): names, JSON types, then the same bounds/pattern checks as validate_request."""
    known = {spec["name"]: spec for spec in entry["options"]}
    unknown = sorted(set(options) - set(known))
    if unknown:
        raise ValueError(f"Unknown option(s) for {entry['id']}: {', '.join(unknown)}.")
    for name, spec in known.items():
        value = options.get(name, spec["default"])
        wanted = int if spec["type"] == "integer" else str
        if not isinstance(value, wanted) or isinstance(value, bool):
            raise ValueError(f"Option {name} must be {'an integer' if wanted is int else 'a string'}.")
        _check_option(spec, value)


def _option_values(entry, options):
    values = {}
    for spec in entry["options"]:
        value = options.get(spec["name"], spec["default"])
        if spec.get("transform") == "upper" and value:
            value = str(value).upper()
        values[spec["name"]] = int(value) if spec["type"] == "integer" else value
    return values


def build_argv(entry, inputs, options):
    values = {"target": inputs["target"], **_option_values(entry, options)}
    flags = next((item.get("flags", {}) for item in entry["inputs"] if item["name"] == "target"), {})
    values["kind_flag"] = flags.get(inputs.get("kind"), "")
    argv = []
    for segment in entry["argv_template"]:
        if segment["when"] and not values.get(segment["when"]):
            continue
        for token in segment["tokens"]:
            if token == "{fixed_argv}":
                argv.extend(entry["fixed_argv"])
                continue
            argv.append(PLACEHOLDER.sub(lambda match: _substitute(match.group(1), values), token))
    return argv


def _substitute(name, values):
    if name not in values:
        raise ValueError(f"Unknown argv placeholder: {{{name}}}")
    return str(values[name])
