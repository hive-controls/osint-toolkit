"""Phone Lookup's project build must not fetch an unhashed build backend."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

PHONE_DIR = Path(__file__).resolve().parent.parent / "Phone Lookup"
LOCK_PATHS = [PHONE_DIR / "requirements.lock", PHONE_DIR / "artifacts" / "requirements.lock"]
SETUPTOOLS_PIN = re.compile(r"^setuptools==\S+ \\\n\s+--hash=sha256:[0-9a-f]{64}", re.MULTILINE)


def project_install_line() -> str:
    dockerfile = (PHONE_DIR / "Dockerfile").read_text(encoding="utf-8")
    joined = dockerfile.replace("\\\n", " ")
    matches = [line for line in joined.splitlines() if "pip install" in line and "/build" in line and "--no-deps" in line]
    return " ".join(matches)


class PhoneBuildPinTests(unittest.TestCase):
    def test_project_install_is_offline_and_unisolated(self):
        line = project_install_line()
        self.assertIn("--no-build-isolation", line)
        self.assertIn("--no-index", line)
        self.assertIn("--no-deps", line)

    def test_locks_pin_setuptools_with_hash(self):
        for lock_path in LOCK_PATHS:
            text = lock_path.read_text(encoding="utf-8")
            self.assertRegex(text, SETUPTOOLS_PIN, str(lock_path))

    def test_both_locks_are_byte_identical(self):
        self.assertEqual(LOCK_PATHS[0].read_bytes(), LOCK_PATHS[1].read_bytes())

    def test_pyproject_license_is_apache(self):
        text = (PHONE_DIR / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, r'(?m)^license\s*=\s*"Apache-2\.0"')


if __name__ == "__main__":
    unittest.main()
