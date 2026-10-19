"""GitHub workflow hygiene: SHA-pinned actions, declared permissions, no pull_request_target, no extra secrets.

Passes vacuously while .github/workflows is absent.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

USES_LINE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
PINNED_SHA = re.compile(r"@[0-9a-f]{40}$")
SECRETS_REF = re.compile(r"secrets\.([A-Za-z0-9_]+)")
PERMISSIONS_KEY = re.compile(r"^\s*permissions:", re.MULTILINE)
PULL_REQUEST_TARGET = re.compile(r"\bpull_request_target\b")


def workflow_problems(name: str, text: str) -> list[str]:
    problems = []
    if not PERMISSIONS_KEY.search(text):
        problems.append(f"{name}: no permissions: declared")
    if PULL_REQUEST_TARGET.search(text):
        problems.append(f"{name}: uses pull_request_target")
    for number, line in enumerate(text.splitlines(), 1):
        match = USES_LINE.match(line)
        if match:
            reference = match.group(1)
            if not reference.startswith("./") and not PINNED_SHA.search(reference):
                problems.append(f"{name}:{number}: unpinned action {reference}")
        for secret in SECRETS_REF.findall(line):
            if secret != "GITHUB_TOKEN":
                problems.append(f"{name}:{number}: secret {secret}")
    return problems


def scan_directory(directory: Path) -> list[str]:
    problems = []
    for workflow in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        problems += workflow_problems(workflow.name, workflow.read_text(encoding="utf-8"))
    return problems


class GithubHygieneTests(unittest.TestCase):
    def test_repo_workflows_are_hygienic(self):
        directory = REPO_ROOT / ".github" / "workflows"
        if not directory.is_dir():
            self.skipTest(".github/workflows absent")
        self.assertEqual(scan_directory(directory), [])

    def test_clean_fixture_passes(self):
        clean = (
            "on: [push]\npermissions:\n  contents: read\njobs:\n  t:\n    steps:\n"
            "      - uses: actions/checkout@" + "a" * 40 + "\n"
            "      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"
        )
        self.assertEqual(workflow_problems("ok.yml", clean), [])

    def test_bad_fixture_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "bad.yml").write_text(
                "on:\n  pull_request_target:\njobs:\n  t:\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - run: echo ${{ secrets.DEPLOY_KEY }}\n",
                encoding="utf-8",
            )
            problems = scan_directory(Path(tmp))
        joined = "\n".join(problems)
        for expected in ("no permissions", "pull_request_target", "unpinned action", "secret DEPLOY_KEY"):
            self.assertIn(expected, joined)


if __name__ == "__main__":
    unittest.main()
