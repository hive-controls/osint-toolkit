"""Static checks for the routed-proxy Squid variants (no Docker needed).

The Docker `squid -k parse` proof is manual/CI and is not exercised here.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = {
    "maigret": "Maigret Docker",
    "phone": "Phone Lookup",
    "scanner": "User-Scanner Docker",
}
DST_ACL = re.compile(r"^\s*acl\s+\S+\s+dst(domain|dom_regex)?\s", re.IGNORECASE | re.MULTILINE)


def read(tool: str, relative: str) -> str:
    return (REPO_ROOT / TOOLS[tool] / relative).read_text(encoding="utf-8")


class SquidVariantTests(unittest.TestCase):
    def test_both_confs_exist_per_tool(self) -> None:
        for tool, directory in TOOLS.items():
            for name in ("squid.conf", "squid-routed.conf", "upstream.default.conf"):
                with self.subTest(tool=tool, conf=name):
                    self.assertTrue((REPO_ROOT / directory / "proxy" / name).is_file())

    def test_routed_conf_includes_upstream_and_forbids_direct(self) -> None:
        for tool in TOOLS:
            with self.subTest(tool=tool):
                text = read(tool, "proxy/squid-routed.conf")
                self.assertRegex(text, r"(?m)^include /etc/squid/upstream\.d/upstream\.conf$")
                self.assertRegex(text, r"(?m)^never_direct allow all$")
                self.assertLess(text.index("never_direct allow all"), text.index("include /etc/squid/upstream.d"))

    def test_routed_conf_denies_ip_literals_and_has_no_dst_acls(self) -> None:
        for tool in TOOLS:
            with self.subTest(tool=tool):
                text = read(tool, "proxy/squid-routed.conf")
                self.assertRegex(text, r"(?m)^acl ip_literal_host url_regex .*\[0-9\]")
                self.assertRegex(text, r"(?m)^http_access deny ip_literal_host$")
                self.assertIsNone(DST_ACL.search(text), "routed conf must not use dst/dstdomain ACLs")
                self.assertIn("cache deny all", text)
                self.assertIn("scanner_net src", text)
                self.assertRegex(text, r"(?m)^dns_nameservers 127\.0\.0\.1$")
                self.assertIn("what routed mode trades away", text.lower())

    def test_vpn_conf_is_unchanged_in_posture(self) -> None:
        for tool in TOOLS:
            with self.subTest(tool=tool):
                text = read(tool, "proxy/squid.conf")
                self.assertIn("acl blocked_ipv4 dst 10.0.0.0/8", text)
                self.assertNotIn("upstream.d", text)

    def test_dockerfile_copies_both_confs_and_creates_upstream_dir(self) -> None:
        for tool in TOOLS:
            with self.subTest(tool=tool):
                text = read(tool, "Dockerfile.proxy")
                self.assertIn("COPY proxy/squid.conf /etc/squid/squid.conf", text)
                self.assertIn("COPY proxy/squid-routed.conf /etc/squid/squid-routed.conf", text)
                self.assertIn("/etc/squid/upstream.d", text)
                self.assertIn("# vpn mode: no upstream peer", text)
                self.assertIn("USER proxy", text)
                self.assertRegex(text, r'ENTRYPOINT \["squid"')

    def test_compose_selects_conf_and_bind_mounts_upstream_read_only(self) -> None:
        for tool in TOOLS:
            with self.subTest(tool=tool):
                text = read(tool, "compose.yaml")
                self.assertIn("OSINT_SQUID_CONF:-squid.conf", text)
                self.assertRegex(text, r"\$\{OSINT_SQUID_UPSTREAM:-\./proxy/upstream\.default\.conf\}:/etc/squid/upstream\.d/upstream\.conf:ro")
                self.assertIn("read_only: true", text)


class RunnerWiringTests(unittest.TestCase):
    RUNNERS = {
        "Maigret Docker/run-maigret.ps1": "maigret",
        "Phone Lookup/run-phone.ps1": "phone",
        "User-Scanner Docker/run-scanner.ps1": "scanner",
    }

    def test_squid_runners_enable_probe_and_clean_up(self) -> None:
        for relative, service in self.RUNNERS.items():
            with self.subTest(runner=relative):
                text = (REPO_ROOT / relative).read_text(encoding="utf-8-sig")
                self.assertIn("OsintProxyWiring.ps1", text)
                self.assertIn("Resolve-OsintProxyEnforcementAction", text)
                self.assertIn("Enable-OsintRoutedProxy", text)
                self.assertIn(f"Invoke-OsintEnforcementProbe -ToolService '{service}'", text)
                self.assertIn("exit 75", text)
                self.assertIn("Disable-OsintRoutedProxy", text)
                self.assertLess(text.index("Enable-OsintRoutedProxy"), text.index("docker compose up"))

    def test_torbot_refuses_routed_proxy(self) -> None:
        text = (REPO_ROOT / "TorBot Docker/run-torbot.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("Resolve-OsintTorBotRouteAction", text)
        self.assertNotIn("Enable-OsintRoutedProxy", text)


if __name__ == "__main__":
    unittest.main()
