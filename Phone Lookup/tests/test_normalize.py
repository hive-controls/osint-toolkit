import unittest

from phone_lookup.normalize import PhoneParseError, describe, parse_number
from phone_lookup.redact import redact


class NormalizeTests(unittest.TestCase):
    def test_e164_us(self):
        parsed = parse_number("+12025550123")
        info = describe(parsed)
        self.assertEqual(info["e164"], "+12025550123")
        self.assertEqual(info["digits"], "12025550123")
        self.assertEqual(info["region"], "US")
        self.assertTrue(info["valid"])
        self.assertIn(info["line_type"], {"fixed_line_or_mobile", "fixed_line", "mobile"})

    def test_national_needs_region(self):
        with self.assertRaises(PhoneParseError):
            parse_number("2025550123")

    def test_national_with_region(self):
        parsed = parse_number("2025550123", "US")
        self.assertEqual(describe(parsed)["e164"], "+12025550123")

    def test_redact_passwords(self):
        payload = {"result": {"password": "hunter2", "email": "a@b.c", "nested": {"hash": "abc"}}}
        out = redact(payload)
        self.assertEqual(out["result"]["password"], "[redacted]")
        self.assertEqual(out["result"]["email"], "a@b.c")
        self.assertEqual(out["result"]["nested"]["hash"], "[redacted]")


if __name__ == "__main__":
    unittest.main()
