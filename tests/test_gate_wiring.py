"""Static checks that every launcher and menu is wired to the shared network gate."""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNNERS = {
    "maigret": "Maigret Docker/run-maigret.ps1",
    "phone": "Phone Lookup/run-phone.ps1",
    "torbot": "TorBot Docker/run-torbot.ps1",
    "scanner": "User-Scanner Docker/run-scanner.ps1",
}
MENUS = {
    "maigret": "Maigret Docker/maigret-menu.ps1",
    "phone": "Phone Lookup/phone-menu.ps1",
    "torbot": "TorBot Docker/torbot-menu.ps1",
    "scanner": "User-Scanner Docker/scanner-menu.ps1",
}


def tracked_files() -> list[str]:
    output = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [line for line in output.splitlines() if line]


class GateWiringTests(unittest.TestCase):
    def test_no_script_mentions_skip_network_gate(self) -> None:
        offenders = [
            name
            for name in tracked_files()
            if name.lower().endswith(".ps1")
            and (REPO_ROOT / name).is_file()
            and "SkipNetworkGate" in (REPO_ROOT / name).read_text(encoding="utf-8-sig")
        ]
        self.assertEqual(offenders, [])

    def test_runners_import_and_assert_before_compose(self) -> None:
        for tool, relative in RUNNERS.items():
            with self.subTest(tool=tool):
                text = (REPO_ROOT / relative).read_text(encoding="utf-8-sig")
                self.assertIn("OsintNetworkGate.psm1", text)
                assert_match = re.search(rf"Invoke-OsintNetworkGate\s+-Tool\s+{tool}\b", text)
                self.assertIsNotNone(assert_match, "runner does not invoke the gate")
                self.assertNotRegex(text, r"Test-OsintNetworkGate\s+-Tool[^\r\n]*-Quiet", "runner re-probes on its exit path")
                compose_index = text.find("docker compose")
                self.assertGreater(compose_index, -1)
                self.assertLess(assert_match.start(), compose_index)

    def test_menus_probe_the_gate(self) -> None:
        for tool, relative in MENUS.items():
            with self.subTest(tool=tool):
                text = (REPO_ROOT / relative).read_text(encoding="utf-8-sig")
                self.assertRegex(text, rf"Test-OsintNetworkGate\s+-Tool\s+{tool}\b")

    def test_per_tool_gate_probes_removed(self) -> None:
        leftovers = [n for n in tracked_files() if n.endswith("gate/Test-NetworkGate.ps1")]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
