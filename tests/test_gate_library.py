"""Static wiring checks for the shared network-gate library (no PowerShell needed)."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "shared" / "OsintNetworkGate.psm1"
EXAMPLE_PATH = REPO_ROOT / "shared" / "gate" / "osint-gate.example.json"
PUBLIC_FUNCTIONS = [
    "Test-OsintNetworkGate",
    "Invoke-OsintNetworkGate",
    "Assert-OsintNetworkGate",
    "Test-OsintInformationalArguments",
    "Get-OsintGateExitCode",
    "ConvertTo-OsintSquidUpstreamConfig",
]
EXIT_STATEMENT = re.compile(r"^\s*exit\b", re.IGNORECASE)


class GateLibraryWiringTests(unittest.TestCase):
    def test_module_exists(self) -> None:
        self.assertTrue(MODULE_PATH.is_file(), f"missing {MODULE_PATH}")

    def test_module_exports_public_functions(self) -> None:
        text = MODULE_PATH.read_text(encoding="utf-8")
        match = re.search(r"Export-ModuleMember\s+-Function\s+([^\r\n#]+)", text)
        self.assertIsNotNone(match, "no explicit Export-ModuleMember -Function")
        exported = {name.strip(" ,'\"") for name in re.split(r"[,\s]+", match.group(1)) if name}
        self.assertEqual(exported, set(PUBLIC_FUNCTIONS))

    def test_shared_example_config(self) -> None:
        data = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(data.get("schemaVersion"), 1)
        self.assertGreaterEqual(len(data.get("vpnNamePatterns", [])), 1)
        self.assertEqual(data.get("mode"), "vpn")
        self.assertIn("routedProxy", data.get("notes", ""))

    def test_shared_scripts_never_exit(self) -> None:
        offenders = []
        for script in sorted((REPO_ROOT / "shared").rglob("*")):
            if script.suffix.lower() not in {".ps1", ".psm1"}:
                continue
            for line_number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
                if EXIT_STATEMENT.match(line):
                    offenders.append(f"{script.relative_to(REPO_ROOT)}:{line_number}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
