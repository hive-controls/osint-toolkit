import json
import unittest

from osint_profiler.adapters import inspect


def phone_payload(skipped):
    return {"tool": "phone-lookup", "local": {"e164": "+15555550123"},
            "sources": {"hudson_rock": {"ok": True, "hit": False, "http_status": 429,
                                        "rate_limited": True, "retry_after": 30}},
            "skipped": skipped}


class PhoneSkippedReasons(unittest.TestCase):
    def test_dict_skipped_keeps_reason(self):
        payload = phone_payload({"numverify": "disabled", "dehashed": "skipped-flag"})
        result = inspect(json.dumps(payload).encode(), "phone.json")
        self.assertIn("Provider skipped: numverify (disabled)", result["issues"])
        self.assertIn("Provider skipped: dehashed (skipped-flag)", result["issues"])

    def test_legacy_list_skipped_still_imports(self):
        result = inspect(json.dumps(phone_payload(["numverify"])).encode(), "phone.json")
        self.assertIn("Provider skipped: numverify", result["issues"])

    def test_rate_limit_fields_reach_observation(self):
        result = inspect(json.dumps(phone_payload({})).encode(), "phone.json")
        extra = result["observations"][-1]["extra"]
        self.assertIs(extra["rate_limited"], True)
        self.assertEqual(extra["retry_after"], 30)


if __name__ == "__main__":
    unittest.main()
