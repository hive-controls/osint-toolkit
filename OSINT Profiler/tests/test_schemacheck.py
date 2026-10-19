import unittest
from osint_profiler.schemacheck import validate

try:
    import jsonschema
except ImportError:
    jsonschema = None

# (name, schema, instance, accepted)
FIXTURES = [
    ("type-string-ok", {"type": "string"}, "x", True),
    ("type-string-bad", {"type": "string"}, 5, False),
    ("type-integer-ok", {"type": "integer"}, 5, True),
    ("type-integer-rejects-bool", {"type": "integer"}, True, False),
    ("type-integer-rejects-float", {"type": "integer"}, 1.5, False),
    ("type-number-accepts-int", {"type": "number"}, 3, True),
    ("type-number-rejects-bool", {"type": "number"}, False, False),
    ("type-boolean", {"type": "boolean"}, True, True),
    ("type-null", {"type": "null"}, None, True),
    ("type-array-bad", {"type": "array"}, {}, False),
    ("type-object-bad", {"type": "object"}, [], False),
    ("type-union-ok", {"type": ["string", "null"]}, None, True),
    ("type-union-bad", {"type": ["string", "null"]}, 4, False),
    ("enum-ok", {"enum": ["a", "b"]}, "a", True),
    ("enum-bad", {"enum": ["a", "b"]}, "c", False),
    ("enum-bool-is-not-int", {"enum": [1]}, True, False),
    ("const-ok", {"const": 1}, 1, True),
    ("const-bad", {"const": 1}, 2, False),
    ("const-bool-is-not-int", {"const": 1}, True, False),
    ("required-ok", {"type": "object", "required": ["a"]}, {"a": 1}, True),
    ("required-missing", {"type": "object", "required": ["a"]}, {}, False),
    ("properties-ok", {"properties": {"a": {"type": "integer"}}}, {"a": 1}, True),
    ("properties-bad-child", {"properties": {"a": {"type": "integer"}}}, {"a": "x"}, False),
    ("properties-extra-allowed", {"properties": {"a": {}}}, {"b": 1}, True),
    ("additional-false-ok", {"properties": {"a": {}}, "additionalProperties": False}, {"a": 1}, True),
    ("additional-false-bad", {"properties": {"a": {}}, "additionalProperties": False}, {"a": 1, "b": 2}, False),
    ("additional-schema-ok", {"additionalProperties": {"type": "integer"}}, {"x": 1}, True),
    ("additional-schema-bad", {"additionalProperties": {"type": "integer"}}, {"x": "s"}, False),
    ("items-ok", {"items": {"type": "integer"}}, [1, 2], True),
    ("items-bad", {"items": {"type": "integer"}}, [1, "x"], False),
    ("pattern-ok", {"pattern": "^[a-z]+$"}, "abc", True),
    ("pattern-bad", {"pattern": "^[a-z]+$"}, "ab1", False),
    ("pattern-unanchored-searches", {"pattern": "b"}, "abc", True),
    ("pattern-ignores-non-string", {"pattern": "^x$"}, 5, True),
    ("minlength-ok", {"minLength": 2}, "ab", True),
    ("minlength-bad", {"minLength": 2}, "a", False),
    ("maxlength-ok", {"maxLength": 2}, "ab", True),
    ("maxlength-bad", {"maxLength": 2}, "abc", False),
    ("minimum-ok", {"minimum": 1}, 1, True),
    ("minimum-bad", {"minimum": 1}, 0, False),
    ("maximum-ok", {"maximum": 10}, 10, True),
    ("maximum-bad", {"maximum": 10}, 11, False),
    ("minimum-ignores-bool", {"minimum": 1}, False, True),
    ("ref-defs-ok", {"$defs": {"n": {"type": "integer"}}, "properties": {"a": {"$ref": "#/$defs/n"}}}, {"a": 1}, True),
    ("ref-defs-bad", {"$defs": {"n": {"type": "integer"}}, "properties": {"a": {"$ref": "#/$defs/n"}}}, {"a": "x"}, False),
    ("ref-nested-ok", {"$defs": {"n": {"type": "integer"}, "l": {"type": "array", "items": {"$ref": "#/$defs/n"}}}, "$ref": "#/$defs/l"}, [1, 2], True),
    ("ref-nested-bad", {"$defs": {"n": {"type": "integer"}, "l": {"type": "array", "items": {"$ref": "#/$defs/n"}}}, "$ref": "#/$defs/l"}, [1, "x"], False),
    ("annotations-ignored", {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "x", "title": "t", "description": "d", "default": 1, "type": "integer"}, 3, True),
    ("true-schema", True, "anything", True),
    ("false-schema", False, "anything", False),
]


class SchemaCheck(unittest.TestCase):
    def test_each_keyword_accepts_and_rejects(self):
        for name, schema, instance, accepted in FIXTURES:
            with self.subTest(name=name):
                errors = validate(instance, schema)
                self.assertEqual(errors == [], accepted, errors)

    def test_errors_carry_the_instance_path(self):
        schema = {"properties": {"a": {"items": {"type": "integer"}}}}
        errors = validate({"a": [1, "x"]}, schema)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("$.a[1]"), errors)

    def test_required_error_names_the_missing_property(self):
        errors = validate({}, {"required": ["alpha"]})
        self.assertTrue(any("alpha" in message for message in errors), errors)

    def test_unsupported_assertion_keyword_fails_loudly(self):
        for keyword in ("oneOf", "anyOf", "allOf", "not", "patternProperties", "uniqueItems", "if"):
            with self.subTest(keyword=keyword), self.assertRaises(ValueError):
                validate(1, {keyword: []})

    def test_min_items_is_enforced(self):
        self.assertTrue(validate([], {"minItems": 1}))
        self.assertEqual(validate([1], {"minItems": 1}), [])

    def test_unresolvable_ref_fails_loudly(self):
        with self.assertRaises(ValueError):
            validate(1, {"$ref": "#/$defs/missing"})
        with self.assertRaises(ValueError):
            validate(1, {"$ref": "https://example.test/x.json"})

    def test_ref_cycle_without_progress_is_rejected(self):
        with self.assertRaises(ValueError):
            validate(1, {"$defs": {"a": {"$ref": "#/$defs/a"}}, "$ref": "#/$defs/a"})

    @unittest.skipIf(jsonschema is None, "third-party jsonschema not installed (dev-only cross-check)")
    def test_agrees_with_reference_implementation(self):
        for name, schema, instance, _ in FIXTURES:
            with self.subTest(name=name):
                reference = jsonschema.Draft202012Validator(schema).is_valid(instance)
                self.assertEqual(validate(instance, schema) == [], reference)


if __name__ == "__main__":
    unittest.main()
