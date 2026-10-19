"""Public-tree guardrails: no case data, databases, secrets, or key-shaped strings tracked."""
from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:  # source tree only; the public repository has no private set, so every tracked path is public
    from private_paths import PRIVATE_FILES, PRIVATE_PREFIXES  # noqa: E402
except ImportError:
    PRIVATE_PREFIXES, PRIVATE_FILES = (), ()

REPO_ROOT = Path(__file__).resolve().parent.parent

ALLOWED_OSINT_PATHS = {
    "OSINT/New-OsintCase.ps1",
    "OSINT/README.md",
    "OSINT/cases/_template/case.md",
}
DATABASE_PATH = re.compile(r"\.(sqlite|sqlite3|db)(-wal|-shm)?$")

MUST_BE_IGNORED = [
    "OSINT/cases/x/case.md",
    "OSINT/cases/x/case.sqlite",
    "OSINT/maigret/x.json",
    "OSINT/maigret_saved_reports/x",
    "OSINT/maigret-output/x",
    "OSINT/phone/x.json",
    "OSINT/scanner/x/results.json",
    "OSINT/torbot/x",
    "OSINT/inbox/inbox.sqlite",
    "OSINT/inbox.sqlite",
    "OSINT/inbox.sqlite-wal",
    "OSINT/.profiler/x",
    "OSINT/.profiler.sqlite",
    "OSINT/.profiler-locks/x",
    "OSINT Profiler/runtime.json",
    "Phone Lookup/secrets.json",
]
DOCKER_DIRS = ["Phone Lookup", "Maigret Docker", "TorBot Docker", "User-Scanner Docker"]
MUST_BE_TRACKABLE = ["OSINT/cases/_template/case.md"]

KEY_SHAPES = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|eyJ[A-Za-z0-9_-]{20,}\.eyJ"
)
SKIP_SUFFIXES = (".lock", ".whl", ".png", ".jpg", ".ico", ".gz", ".tar")

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def tracked_paths() -> list[str]:
    output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True
    ).stdout
    return [p for p in output.decode("utf-8", "surrogateescape").split("\0") if p]


def public_tree_paths() -> list[str]:
    return [
        p for p in tracked_paths() if not p.startswith(PRIVATE_PREFIXES) and p not in PRIVATE_FILES
    ]


def shippable_paths() -> list[str]:
    return [
        p
        for p in public_tree_paths()
        if not p.endswith("THIRD-PARTY-NOTICES.md") and not p.endswith(SKIP_SUFFIXES)
    ]


def read_text_or_none(relative_path: str) -> str | None:
    full = REPO_ROOT / relative_path
    if not full.is_file():
        return None
    data = full.read_bytes()
    if b"\0" in data:
        return None
    return data.decode("utf-8", "replace")


def find_term_hits(patterns: dict[str, str]) -> list[str]:
    compiled = {name: re.compile(pattern) for name, pattern in patterns.items()}
    hits = []
    for path in shippable_paths():
        text = read_text_or_none(path)
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for name, pattern in compiled.items():
                if pattern.search(line):
                    hits.append(f"{path}:{line_number} [{name}]")
    return hits


def strip_code_fences(text: str) -> list[tuple[int, str]]:
    kept, in_fence = [], False
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            kept.append((line_number, line))
    return kept


def resolve_relative(source: str, target: str) -> str:
    resolved = (Path(source).parent / unquote(target.split("#")[0])).as_posix()
    parts: list[str] = []
    for part in resolved.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in (".", ""):
            parts.append(part)
    return "/".join(parts)


def find_broken_links(markdown_by_path: dict[str, str], known_paths: set[str]) -> list[str]:
    broken = []
    for path, text in markdown_by_path.items():
        for line_number, line in strip_code_fences(text):
            for target in LINK.findall(line):
                if re.match(r"[a-z]+:", target) or target.startswith("#"):
                    continue
                resolved = resolve_relative(path, target)
                if resolved in known_paths or any(k.startswith(resolved + "/") for k in known_paths):
                    continue
                broken.append(f"{path}:{line_number} -> {target}")
    return broken


def is_ignored(path: str) -> bool:
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", path], cwd=REPO_ROOT, capture_output=True
    )
    return result.returncode == 0


BINARY_ARTIFACT_PATH = re.compile(r"(\.whl|\.tar|\.tar\.gz)$|(^|/)artifacts/wheelhouse(/|$)")


def is_binary_artifact(path: str) -> bool:
    return BINARY_ARTIFACT_PATH.search(path) is not None


class PublicTreeTests(unittest.TestCase):
    def test_binary_artifact_predicate(self):
        for hit in [
            "Maigret Docker/artifacts/wheelhouse/x-1-py3-none-any.whl",
            "a/artifacts/wheelhouse/readme.txt",
            "a/x.whl",
            "image.tar",
            "images/maigret.tar.gz",
        ]:
            self.assertTrue(is_binary_artifact(hit), hit)
        for miss in [
            "Maigret Docker/artifacts/requirements.lock",
            "shared/build/fetch_wheelhouse.py",
            "docs/wheelhouse.md",
            "Maigret Docker/artifacts/wheelhouse.manifest.txt",
        ]:
            self.assertFalse(is_binary_artifact(miss), miss)

    def test_no_tracked_wheels_or_image_tarballs(self):
        offenders = [p for p in tracked_paths() if is_binary_artifact(p)]
        self.assertEqual(offenders, [])

    def test_wheelhouse_manifest_is_ignored(self):
        probes = [f"{d}/artifacts/wheelhouse.manifest.txt" for d in DOCKER_DIRS]
        self.assertEqual([p for p in probes if not is_ignored(p)], [])

    def test_no_tracked_case_data_paths(self):
        offenders = [
            p for p in tracked_paths() if p.startswith("OSINT/") and p not in ALLOWED_OSINT_PATHS
        ]
        self.assertEqual(offenders, [])

    def test_no_tracked_databases_or_secrets(self):
        offenders = [
            p
            for p in tracked_paths()
            if DATABASE_PATH.search(p) or p.rsplit("/", 1)[-1] == "secrets.json"
        ]
        self.assertEqual(offenders, [])

    def test_sensitive_probe_paths_are_ignored(self):
        probes = list(MUST_BE_IGNORED)
        probes += [f"{d}/artifacts/wheelhouse/x.whl" for d in DOCKER_DIRS]
        not_ignored = [p for p in probes if not is_ignored(p)]
        self.assertEqual(not_ignored, [])

    def test_template_is_not_ignored(self):
        still_ignored = [p for p in MUST_BE_TRACKABLE if is_ignored(p)]
        self.assertEqual(still_ignored, [])

    def test_no_key_shaped_strings_in_tracked_text(self):
        hits = []
        for path in tracked_paths():
            full = REPO_ROOT / path
            if not full.is_file() or path.endswith(".lock"):
                continue
            data = full.read_bytes()
            if b"\0" in data:
                continue
            text = data.decode("utf-8", "replace")
            for line_number, line in enumerate(text.splitlines(), 1):
                if "--hash=sha" in line:
                    continue
                if KEY_SHAPES.search(line):
                    hits.append(f"{path}:{line_number}")
        self.assertEqual(hits, [])


class LegalUseNoticeTests(unittest.TestCase):
    CASE_PHRASE = "I AUTHORIZE THIS CASE AND ACCEPT RESPONSIBILITY FOR LAWFUL USE"
    PROVIDER_PHRASE = "I HAVE READ THE <PROVIDER> TERMS AND ACCEPT RESPONSIBILITY FOR MY QUERIES"
    BANNER_PREFIX = "> People-focused OSINT. Authorized, lawful use only — see [LEGAL-USE.md]("
    README_PATHS = [
        "README.md",
        "OSINT/README.md",
        "OSINT Profiler/README.md",
        "Phone Lookup/README.md",
        "Maigret Docker/README.md",
        "TorBot Docker/README.md",
        "User-Scanner Docker/README.md",
    ]

    def test_legal_use_exists_with_both_gate_phrases(self):
        legal_use = REPO_ROOT / "LEGAL-USE.md"
        self.assertTrue(legal_use.is_file())
        text = legal_use.read_text(encoding="utf-8")
        self.assertTrue(text.strip())
        self.assertIn(self.CASE_PHRASE, text)
        self.assertIn(self.PROVIDER_PHRASE, text)

    def test_every_tool_readme_carries_the_banner_line(self):
        missing = []
        for readme_path in self.README_PATHS:
            text = (REPO_ROOT / readme_path).read_text(encoding="utf-8")
            if not any(line.startswith(self.BANNER_PREFIX) for line in text.splitlines()):
                missing.append(readme_path)
        self.assertEqual(missing, [])


class LicensingFilesTests(unittest.TestCase):
    def test_license_is_apache_2(self):
        text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", text)
        self.assertIn("Version 2.0", text)

    def test_notice_names_owner_and_upstream_author(self):
        text = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("Hive Controls", text)
        self.assertIn("Kaif", text)

    def test_every_tool_has_third_party_notices(self):
        missing = [
            d for d in DOCKER_DIRS if not (REPO_ROOT / d / "THIRD-PARTY-NOTICES.md").is_file()
        ]
        self.assertEqual(missing, [])

    def test_readme_has_gpl_boundary_section(self):
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("## Licensing and the GPL boundary", text)


class MarkdownLinkTests(unittest.TestCase):
    def test_relative_markdown_links_resolve_to_tracked_paths(self):
        known = set(public_tree_paths())
        markdown = {}
        for path in shippable_paths():
            if path.endswith(".md"):
                text = read_text_or_none(path)
                if text is not None:
                    markdown[path] = text
        self.assertEqual(find_broken_links(markdown, known), [])

    def test_link_checker_flags_a_broken_link(self):
        broken = find_broken_links({"a/x.md": "see [gone](missing.md)"}, {"a/x.md"})
        self.assertEqual(broken, ["a/x.md:1 -> missing.md"])
        ok = find_broken_links({"a/x.md": "see [y](../a/x.md)\n```\n[z](nope.md)\n```"}, {"a/x.md"})
        self.assertEqual(ok, [])


if __name__ == "__main__":
    unittest.main()
