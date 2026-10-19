import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from phone_lookup import cli
from phone_lookup.providers import dehashed, hudson, leakcheck, leakradar, numverify

NUMBER = "+12025550123"
PROVIDERS = ("numverify", "hudson_rock", "dehashed", "leakcheck", "leakradar")
KEY_ENV = {
    "numverify": "NUMVERIFY_API_KEY",
    "dehashed": "DEHASHED_API_KEY",
    "leakcheck": "LEAKCHECK_APIKEY",
    "leakradar": "LEAKRADAR_API_KEY",
}
PROVIDER_MODULES = {
    "numverify": numverify,
    "hudson_rock": hudson,
    "dehashed": dehashed,
    "leakcheck": leakcheck,
    "leakradar": leakradar,
}
ENV_TO_CLEAR = (
    "NUMVERIFY_API_KEY", "APILAYER_API_KEY", "DEHASHED_API_KEY", "LEAKCHECK_APIKEY",
    "LEAKCHECK_API_KEY", "LEAKRADAR_API_KEY", "LEAKRADAR_TOKEN", "PHONE_LOOKUP_PROVIDERS",
    "PHONE_LOOKUP_PROVIDERS_FILE", "PHONE_LOOKUP_REQUIRE_CASE", "OSINT_SUBJECT_AUTH",
    "PHONE_LOOKUP_OPERATOR",
)


def _providers_config():
    from phone_lookup import providers_config
    return providers_config


class ProviderTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.providers_path = root / "providers.json"
        self.output_dir = root / "out"
        patcher = mock.patch.dict(os.environ, {
            "PHONE_LOOKUP_SECRETS": str(root / "secrets.json"),
            "PHONE_LOOKUP_PROVIDERS_FILE": str(self.providers_path),
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ENV_TO_CLEAR:
            if name not in ("PHONE_LOOKUP_SECRETS", "PHONE_LOOKUP_PROVIDERS_FILE"):
                os.environ.pop(name, None)
        self.calls = []
        self.status = 200
        self.body = {}
        for name, module in PROVIDER_MODULES.items():
            for transport in ("get_json", "post_json"):
                if hasattr(module, transport):
                    patcher = mock.patch.object(module, transport, side_effect=self._fake(name))
                    patcher.start()
                    self.addCleanup(patcher.stop)

    def _fake(self, name):
        def transport(*args, **kwargs):
            self.calls.append(name)
            return self.status, self.body
        return transport

    def set_keys(self, *names):
        for name in names:
            os.environ[KEY_ENV[name]] = "test-key"

    def write_config(self, provider, enabled=True, version="current"):
        if version == "current":
            version = _providers_config().terms_version(provider)
        config = {}
        if self.providers_path.is_file():
            config = json.loads(self.providers_path.read_text(encoding="utf-8"))
        config[provider] = {"enabled": enabled, "terms_ack": {"version": version, "operator": "t", "ts": "x"}}
        self.providers_path.write_text(json.dumps(config), encoding="utf-8")

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def lookup(self, *extra):
        return self.run_cli([NUMBER, "--json-only", "-o", str(self.output_dir), *extra])


class ProviderMatrixTests(ProviderTestCase):
    def test_key_alone_never_enables(self):
        for provider in PROVIDERS:
            with self.subTest(provider=provider):
                self.calls.clear()
                self.set_keys(*KEY_ENV)
                code, out, _ = self.lookup()
                self.assertEqual(code, 0)
                self.assertEqual(self.calls, [])
                self.assertEqual(json.loads(out)["skipped"][provider], "disabled")

    def test_enabled_without_key_is_config_error_except_hudson(self):
        for provider in PROVIDERS:
            with self.subTest(provider=provider):
                self.calls.clear()
                self.providers_path.unlink(missing_ok=True)
                self.write_config(provider)
                code, out, _ = self.lookup()
                if provider == "hudson_rock":
                    self.assertEqual(code, 0)
                    self.assertEqual(self.calls, ["hudson_rock"])
                else:
                    self.assertEqual(code, 78)
                    self.assertEqual(self.calls, [])
                    self.assertEqual(json.loads(out)["problems"][provider], "no-key")

    def test_enabled_with_stale_ack_is_config_error(self):
        for provider in PROVIDERS:
            with self.subTest(provider=provider):
                self.calls.clear()
                self.providers_path.unlink(missing_ok=True)
                self.set_keys(*KEY_ENV)
                self.write_config(provider, version="0" * 64)
                code, out, _ = self.lookup()
                self.assertEqual(code, 78)
                self.assertEqual(self.calls, [])
                self.assertEqual(json.loads(out)["problems"][provider], "terms-ack-stale")

    def test_enabled_key_and_current_ack_is_called(self):
        for provider in PROVIDERS:
            with self.subTest(provider=provider):
                self.calls.clear()
                self.providers_path.unlink(missing_ok=True)
                self.set_keys(*KEY_ENV)
                self.write_config(provider)
                code, out, _ = self.lookup()
                self.assertEqual(code, 0)
                self.assertEqual(self.calls, [provider])
                self.assertIn(provider, json.loads(out)["sources"])

    def test_skip_flag_wins_over_enabled(self):
        self.set_keys(*KEY_ENV)
        self.write_config("hudson_rock")
        code, out, _ = self.lookup("--skip-hudson")
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(json.loads(out)["skipped"]["hudson_rock"], "skipped-flag")

    def test_skip_flag_on_disabled_provider_reports_disabled(self):
        code, out, _ = self.lookup("--skip-hudson")
        self.assertEqual(json.loads(out)["skipped"]["hudson_rock"], "disabled")

    def test_env_list_replaces_file_and_requires_current_version(self):
        version = _providers_config().terms_version("hudson_rock")
        os.environ["PHONE_LOOKUP_PROVIDERS"] = f"hudson_rock@{version}"
        code, _, _ = self.lookup()
        self.assertEqual((code, self.calls), (0, ["hudson_rock"]))
        self.calls.clear()
        os.environ["PHONE_LOOKUP_PROVIDERS"] = "hudson_rock"
        code, _, _ = self.lookup()
        self.assertEqual((code, self.calls), (78, []))
        self.calls.clear()
        os.environ["PHONE_LOOKUP_PROVIDERS"] = ""
        self.write_config("hudson_rock")
        code, out, _ = self.lookup()
        self.assertEqual((code, self.calls), (0, []))


class SkippedAndRateLimitTests(ProviderTestCase):
    def test_skipped_is_dict_of_reason_strings(self):
        _, out, _ = self.lookup()
        skipped = json.loads(out)["skipped"]
        self.assertIsInstance(skipped, dict)
        self.assertEqual(set(skipped), set(PROVIDERS))
        self.assertEqual(set(skipped.values()), {"disabled"})

    def test_http_429_is_flagged_without_retry(self):
        self.status = 429
        self.body = {"retry_after": 30}
        self.write_config("hudson_rock")
        _, out, _ = self.lookup()
        self.assertEqual(self.calls, ["hudson_rock"])
        source = json.loads(out)["sources"]["hudson_rock"]
        self.assertIs(source["rate_limited"], True)
        self.assertEqual(source["retry_after"], 30)

    def test_http_200_is_not_flagged(self):
        self.write_config("hudson_rock")
        _, out, _ = self.lookup()
        self.assertNotIn("rate_limited", json.loads(out)["sources"]["hudson_rock"])


class EnableFlowTests(ProviderTestCase):
    def phrase(self, provider="hudson_rock"):
        return f"I HAVE READ THE {provider.upper()} TERMS AND ACCEPT RESPONSIBILITY FOR MY QUERIES"

    def test_wrong_phrase_writes_nothing(self):
        code, _, _ = self.run_cli(["--enable", "hudson_rock", "--acknowledge-terms", "yes"])
        self.assertEqual(code, 2)
        self.assertFalse(self.providers_path.exists())

    def test_missing_phrase_writes_nothing(self):
        code, _, _ = self.run_cli(["--enable", "hudson_rock"])
        self.assertEqual(code, 2)
        self.assertFalse(self.providers_path.exists())

    def test_phrase_of_another_provider_is_rejected(self):
        code, _, _ = self.run_cli(["--enable", "dehashed", "--acknowledge-terms", self.phrase("hudson_rock")])
        self.assertEqual(code, 2)
        self.assertFalse(self.providers_path.exists())

    def test_correct_phrase_records_version_operator_and_timestamp(self):
        os.environ["PHONE_LOOKUP_OPERATOR"] = "analyst-1"
        code, _, _ = self.run_cli(["--enable", "hudson_rock", "--acknowledge-terms", self.phrase()])
        self.assertEqual(code, 0)
        entry = json.loads(self.providers_path.read_text(encoding="utf-8"))["hudson_rock"]
        self.assertIs(entry["enabled"], True)
        self.assertEqual(entry["terms_ack"]["version"], _providers_config().terms_version("hudson_rock"))
        self.assertEqual(entry["terms_ack"]["operator"], "analyst-1")
        self.assertTrue(entry["terms_ack"]["ts"])
        code, _, _ = self.lookup()
        self.assertEqual((code, self.calls), (0, ["hudson_rock"]))

    def test_unknown_provider_is_rejected(self):
        code, _, _ = self.run_cli(["--enable", "nosuch", "--acknowledge-terms", self.phrase("nosuch")])
        self.assertEqual(code, 2)

    def test_disable_turns_provider_off(self):
        self.write_config("hudson_rock")
        code, _, _ = self.run_cli(["--disable", "hudson_rock"])
        self.assertEqual(code, 0)
        self.assertEqual(self.lookup()[0], 0)
        self.assertEqual(self.calls, [])

    def test_providers_listing_json(self):
        self.write_config("hudson_rock")
        self.write_config("dehashed", version="0" * 64)
        code, out, _ = self.run_cli(["--providers", "--json"])
        self.assertEqual(code, 0)
        states = json.loads(out)["providers"]
        self.assertEqual(set(states), set(PROVIDERS))
        self.assertEqual(states["hudson_rock"]["terms_ack"], "current")
        self.assertEqual(states["dehashed"]["terms_ack"], "stale")
        self.assertIs(states["numverify"]["enabled"], False)

    def test_informational_commands_need_no_case(self):
        os.environ["PHONE_LOOKUP_REQUIRE_CASE"] = "1"
        for argv in (["--providers"], ["--version"], ["--disable", "hudson_rock"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_cli(argv)[0], 0)


class RequireCaseTests(ProviderTestCase):
    def test_lookup_refused_without_subject_authorization(self):
        os.environ["PHONE_LOOKUP_REQUIRE_CASE"] = "1"
        self.write_config("hudson_rock")
        code, out, _ = self.lookup()
        self.assertEqual(code, 77)
        self.assertEqual(json.loads(out), {"error": "subject-authorization-required"})
        self.assertEqual(self.calls, [])

    def test_blank_subject_authorization_is_refused(self):
        os.environ["PHONE_LOOKUP_REQUIRE_CASE"] = "1"
        os.environ["OSINT_SUBJECT_AUTH"] = "  "
        self.assertEqual(self.lookup()[0], 77)

    def test_lookup_runs_with_subject_authorization(self):
        os.environ["PHONE_LOOKUP_REQUIRE_CASE"] = "1"
        os.environ["OSINT_SUBJECT_AUTH"] = "/case/auth.json"
        self.assertEqual(self.lookup()[0], 0)

    def test_no_refusal_when_not_required(self):
        self.assertEqual(self.lookup()[0], 0)


class ShippedFilesTests(unittest.TestCase):
    def test_every_provider_has_terms_and_example_is_all_disabled(self):
        config = _providers_config()
        root = Path(__file__).resolve().parents[1]
        for provider in PROVIDERS:
            self.assertRegex(config.terms_version(provider), r"^[0-9a-f]{64}$")
        example = json.loads((root / "providers.example.json").read_text(encoding="utf-8"))
        self.assertEqual(set(example), set(PROVIDERS))
        self.assertTrue(all(entry["enabled"] is False for entry in example.values()))


if __name__ == "__main__":
    unittest.main()
