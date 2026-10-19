"""Static checks that every runner asserts subject authorization after the network gate and that compose plumbs the attestation."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNERS = {
    "maigret": "Maigret Docker/run-maigret.ps1",
    "phone": "Phone Lookup/run-phone.ps1",
    "torbot": "TorBot Docker/run-torbot.ps1",
    "scanner": "User-Scanner Docker/run-scanner.ps1",
}
COMPOSE_FILES = {
    "maigret": "Maigret Docker/compose.yaml",
    "phone": "Phone Lookup/compose.yaml",
    "torbot": "TorBot Docker/compose.yaml",
    "scanner": "User-Scanner Docker/compose.yaml",
}
MENUS = {
    "maigret": "Maigret Docker/maigret-menu.ps1",
    "phone": "Phone Lookup/phone-menu.ps1",
    "torbot": "TorBot Docker/torbot-menu.ps1",
    "scanner": "User-Scanner Docker/scanner-menu.ps1",
}


def read(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8-sig")


class AuthorizationWiringTests(unittest.TestCase):
    def test_runners_assert_after_gate_and_before_compose(self) -> None:
        for tool, relative in RUNNERS.items():
            with self.subTest(tool=tool):
                text = read(relative)
                self.assertIn("OsintSubjectAuthorization.ps1", text)
                gate = re.search(rf"Invoke-OsintNetworkGate\s+-Tool\s+{tool}\b", text)
                assertion = re.search(rf"Assert-OsintSubjectAuthorization\s+-Tool\s+{tool}\s+-Arguments\s+\$\w+", text)
                self.assertIsNotNone(assertion, "runner does not assert subject authorization")
                self.assertGreater(assertion.start(), gate.start())
                self.assertLess(assertion.start(), text.find("docker compose"))
                self.assertRegex(text, r"exit\s+\$authorizationResult\.ExitCode")

    def test_runner_dot_sources_the_authorization_script_after_the_gate_module(self) -> None:
        for tool, relative in RUNNERS.items():
            with self.subTest(tool=tool):
                text = read(relative)
                self.assertLess(text.find("OsintNetworkGate.psm1"), text.find("OsintSubjectAuthorization.ps1"))

    def test_compose_plumbs_the_attestation_into_the_tool_service(self) -> None:
        for tool, relative in COMPOSE_FILES.items():
            with self.subTest(tool=tool):
                text = read(relative)
                service = text[text.index(f"\n  {tool}:"):]
                self.assertIn("OSINT_SUBJECT_AUTH: ${OSINT_SUBJECT_AUTH:-}", service)

    def test_menus_require_a_case_before_running(self) -> None:
        for tool, relative in MENUS.items():
            with self.subTest(tool=tool):
                text = read(relative)
                self.assertIn("OsintSubjectAuthorization.ps1", text)
                self.assertRegex(text, r"if\s+\(-not\s+\(Test-OsintCaseContext\)\)\s*\{\s*Write-OsintCaseRequired")


if __name__ == "__main__":
    unittest.main()
