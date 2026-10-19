"""Static checks: each tool Dockerfile installs offline, hash-pinned, binary-only, from a digest-pinned base."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_DIRS = ["Maigret Docker", "Phone Lookup", "TorBot Docker", "User-Scanner Docker"]
PINNED_FROM = re.compile(r"^FROM\s+\S+@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?\s*$", re.IGNORECASE)
REQUIRED_INSTALL_FLAGS = ["--require-hashes", "--no-index", "--only-binary=:all:"]


def install_run_block(dockerfile_text: str) -> str:
    """The RUN instruction (with line continuations joined) that pip-installs the lock."""
    joined = dockerfile_text.replace("\\\n", " ")
    for line in joined.splitlines():
        if line.startswith("RUN ") and "-r" in line and "requirements.lock" in line:
            return line
        if line.startswith("RUN ") and "--requirement" in line and "requirements.lock" in line:
            return line
    return ""


def dockerfile_text(tool_dir: str) -> str:
    return (REPO_ROOT / tool_dir / "Dockerfile").read_text(encoding="utf-8")


@pytest.mark.parametrize("tool_dir", TOOL_DIRS)
@pytest.mark.parametrize("flag", REQUIRED_INSTALL_FLAGS)
def test_install_run_carries_flag(tool_dir, flag):
    assert flag in install_run_block(dockerfile_text(tool_dir))


@pytest.mark.parametrize("tool_dir", TOOL_DIRS)
def test_every_from_is_digest_pinned(tool_dir):
    from_lines = [l.strip() for l in dockerfile_text(tool_dir).splitlines() if l.upper().startswith("FROM ")]
    assert from_lines
    assert [l for l in from_lines if not PINNED_FROM.match(l)] == []


def test_install_block_detector_sees_missing_flag():
    text = "RUN pip install \\\n  --only-binary=:all: \\\n  --require-hashes \\\n  --requirement /build/requirements.lock\n"
    block = install_run_block(text)
    assert "--no-index" not in block and "--require-hashes" in block
