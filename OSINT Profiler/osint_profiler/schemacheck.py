"""Stdlib-only JSON Schema subset validator (draft 2020-12 vocabulary actually used by the catalog).

Supported: type, enum, const, required, properties, additionalProperties, items, pattern,
minLength, maxLength, minimum, maximum, minItems, local $ref/$defs. Annotation keywords are ignored.
Any other assertion keyword raises ValueError so a schema can never be silently weakened.
"""
from __future__ import annotations
import re

ANNOTATIONS = {"$schema", "$id", "$comment", "$defs", "title", "description", "default", "examples", "format"}
SUPPORTED = {"type", "enum", "const", "required", "properties", "additionalProperties", "items",
             "pattern", "minLength", "maxLength", "minimum", "maximum", "minItems", "$ref"}


def _is_type(instance, name):
    if name == "null": return instance is None
    if name == "boolean": return isinstance(instance, bool)
    if name == "integer": return isinstance(instance, int) and not isinstance(instance, bool)
    if name == "number": return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if name == "string": return isinstance(instance, str)
    if name == "array": return isinstance(instance, list)
    if name == "object": return isinstance(instance, dict)
    raise ValueError(f"Unknown schema type: {name}")


def _same(left, right):
    return type(left) is type(right) and left == right if isinstance(left, bool) or isinstance(right, bool) else left == right


def _resolve(reference, root):
    if reference == "#": return root
    if not reference.startswith("#/"):
        raise ValueError(f"Only local $ref is supported: {reference}")
    node = root
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise ValueError(f"Unresolvable $ref: {reference}")
        node = node[part]
    return node


def _check_scalar_bounds(instance, schema, path, errors):
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern {schema['pattern']}")
    if _is_type(instance, "number"):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")


def _check_object(instance, schema, path, root, errors, trail):
    for name in schema.get("required", []):
        if name not in instance:
            errors.append(f"{path}: missing required property '{name}'")
    properties = schema.get("properties", {})
    for name, child in properties.items():
        if name in instance:
            _walk(instance[name], child, f"{path}.{name}", root, errors, trail)
    extra = [name for name in instance if name not in properties]
    additional = schema.get("additionalProperties", True)
    for name in extra:
        if additional is False:
            errors.append(f"{path}: additional property '{name}' is not allowed")
        elif additional is not True:
            _walk(instance[name], additional, f"{path}.{name}", root, errors, trail)


def _walk(instance, schema, path, root, errors, trail):
    if schema is True: return
    if schema is False:
        errors.append(f"{path}: no value is allowed here")
        return
    unsupported = set(schema) - SUPPORTED - ANNOTATIONS
    if unsupported:
        raise ValueError(f"Unsupported schema keyword(s): {', '.join(sorted(unsupported))}")
    if "$ref" in schema:
        reference = schema["$ref"]
        if (reference, path) in trail:
            raise ValueError(f"Circular $ref without progress: {reference}")
        _walk(instance, _resolve(reference, root), path, root, errors, trail | {(reference, path)})
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(instance, name) for name in names):
            errors.append(f"{path}: expected {'|'.join(names)}")
            return
    if "enum" in schema and not any(_same(instance, option) for option in schema["enum"]):
        errors.append(f"{path}: not one of {schema['enum']}")
    if "const" in schema and not _same(instance, schema["const"]):
        errors.append(f"{path}: must equal {schema['const']!r}")
    _check_scalar_bounds(instance, schema, path, errors)
    if isinstance(instance, dict):
        _check_object(instance, schema, path, root, errors, trail)
    if isinstance(instance, list) and "minItems" in schema and len(instance) < schema["minItems"]:
        errors.append(f"{path}: fewer than minItems {schema['minItems']}")
    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            _walk(item, schema["items"], f"{path}[{index}]", root, errors, trail)


def validate(instance, schema):
    errors: list[str] = []
    _walk(instance, schema, "$", schema, errors, frozenset())
    return errors
