"""fetch_wheelhouse: lock/wheelhouse verification, docker command shape, Dockerfile parsing."""
from __future__ import annotations

import hashlib
import importlib.util
import shlex
import sys
import zipfile
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "shared" / "build" / "fetch_wheelhouse.py"
DIGEST = "sha256:" + "a" * 64


def load_module():
    spec = importlib.util.spec_from_file_location("fetch_wheelhouse", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fw = load_module()


def make_wheel(directory: Path, filename: str, payload: str = "x") -> str:
    directory.mkdir(parents=True, exist_ok=True)
    wheel_path = directory / filename
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr("pkg/__init__.py", payload)
    return hashlib.sha256(wheel_path.read_bytes()).hexdigest()


def lock_text(pins: list[tuple[str, str, str]]) -> str:
    lines = ["# fixture lock"]
    for name, version, digest in pins:
        lines.append(f"{name}=={version} \\")
        lines.append(f"    --hash=sha256:{digest}")
    return "\n".join(lines) + "\n"


@pytest.fixture
def tool(tmp_path):
    """A tool dir with one pin (user-scanner) and its matching wheel."""
    tool_dir = tmp_path / "User Scanner Docker"
    wheelhouse = tool_dir / "artifacts" / "wheelhouse"
    digest = make_wheel(wheelhouse, "user_scanner-1.5.1.3-py3-none-any.whl")
    (tool_dir / "requirements.lock").write_text(
        lock_text([("user-scanner", "1.5.1.3", digest)]), encoding="utf-8"
    )
    return tool_dir


def problems_for(tool_dir: Path) -> list[str]:
    return fw.verify_wheelhouse(
        tool_dir / "requirements.lock", tool_dir / "artifacts" / "wheelhouse"
    ).problems


def test_verify_ok_with_name_normalization(tool):
    result = fw.verify_wheelhouse(
        tool / "requirements.lock", tool / "artifacts" / "wheelhouse"
    )
    assert result.problems == []
    assert [row.name for row in result.rows] == ["user-scanner"]
    assert result.rows[0].filename == "user_scanner-1.5.1.3-py3-none-any.whl"


def test_normalize_name_collapses_separators():
    assert fw.normalize_name("User_Scanner") == "user-scanner"
    assert fw.normalize_name("a.b__c") == "a-b-c"


def test_missing_wheel_fails(tool):
    (tool / "artifacts" / "wheelhouse" / "user_scanner-1.5.1.3-py3-none-any.whl").unlink()
    assert any("MISSING" in p for p in problems_for(tool))


def test_wrong_sha_fails_naming_wheel(tool):
    wheel = tool / "artifacts" / "wheelhouse" / "user_scanner-1.5.1.3-py3-none-any.whl"
    wheel.write_bytes(wheel.read_bytes() + b"\0")
    found = problems_for(tool)
    assert any("SHA MISMATCH" in p and wheel.name in p for p in found)


def test_one_flipped_byte_fails(tool):
    wheel = tool / "artifacts" / "wheelhouse" / "user_scanner-1.5.1.3-py3-none-any.whl"
    data = bytearray(wheel.read_bytes())
    data[10] ^= 0xFF
    wheel.write_bytes(bytes(data))
    assert any("SHA MISMATCH" in p for p in problems_for(tool))


def test_extra_wheel_fails(tool):
    make_wheel(tool / "artifacts" / "wheelhouse", "stray-1.0-py3-none-any.whl")
    assert any("EXTRA" in p and "stray-1.0" in p for p in problems_for(tool))


def test_extra_non_wheel_file_fails(tool):
    (tool / "artifacts" / "wheelhouse" / "notes.txt").write_text("hi", encoding="utf-8")
    assert any("EXTRA" in p and "notes.txt" in p for p in problems_for(tool))


def test_missing_wheelhouse_dir_reports_all_missing(tmp_path):
    (tmp_path / "requirements.lock").write_text(
        lock_text([("pkg", "1.0", "b" * 64)]), encoding="utf-8"
    )
    result = fw.verify_wheelhouse(tmp_path / "requirements.lock", tmp_path / "nope")
    assert any("MISSING" in p for p in result.problems)


def test_duplicate_lock_mismatch_fails(tool):
    artifacts = tool / "artifacts"
    root_lock = (tool / "requirements.lock").read_text(encoding="utf-8")
    (artifacts / "requirements.lock").write_text(root_lock + "# drift\n", encoding="utf-8")
    assert any("DUPLICATE LOCK" in p for p in fw.verify_duplicate_lock(tool))


def test_duplicate_lock_identical_or_absent_ok(tool):
    assert fw.verify_duplicate_lock(tool) == []
    artifacts = tool / "artifacts"
    (artifacts / "requirements.lock").write_bytes((tool / "requirements.lock").read_bytes())
    assert fw.verify_duplicate_lock(tool) == []


def test_build_docker_command_flags_and_mounts(tmp_path):
    tool_dir = tmp_path / "My Tool Dir"
    image = f"python:3.12-slim-bookworm@{DIGEST}"
    command = fw.build_docker_command(tool_dir, image, user_flag=None)
    for required in ("--require-hashes", "--no-deps", "--only-binary=:all:"):
        assert required in command
    assert image in command
    lock_mounts = [part for part in command if part.endswith("/in/requirements.lock:ro")]
    assert len(lock_mounts) == 1 and "My Tool Dir" in lock_mounts[0]
    out_mounts = [part for part in command if part.endswith(":/out")]
    assert len(out_mounts) == 1 and "My Tool Dir" in out_mounts[0]
    assert "--user" not in command
    rendered = fw.format_command(command)
    assert shlex.split(rendered)[-1] == command[-1]
    assert "'" in rendered or '"' in rendered


def test_build_docker_command_user_flag_on_posix(tmp_path):
    command = fw.build_docker_command(tmp_path, "img@" + DIGEST, user_flag="1000:1000")
    assert command[command.index("--user") + 1] == "1000:1000"


def test_parse_from_line_python_313_user_scanner_shape():
    dockerfile = (
        "# syntax=docker/dockerfile:1.7\n"
        f"FROM python:3.13-slim-bookworm@{DIGEST} AS builder\n"
        "RUN true\n"
        f"FROM python:3.13-slim-bookworm@{DIGEST}\n"
    )
    base = fw.parse_from_line(dockerfile)
    assert base.python_version == "3.13"
    assert base.reference == f"python:3.13-slim-bookworm@{DIGEST}"


def test_parse_from_line_rejects_unpinned():
    with pytest.raises(ValueError):
        fw.parse_from_line("FROM python:3.12-slim-bookworm AS builder\n")


def test_parse_lock_multiple_hashes_and_comments():
    text = "# c\nfoo_bar==1.0 \\\n    --hash=sha256:" + "c" * 64 + " \\\n    --hash=sha256:" + "d" * 64 + "\n"
    pins = fw.parse_lock(text)
    assert len(pins) == 1
    assert pins[0].name == "foo-bar" and pins[0].version == "1.0"
    assert pins[0].hashes == {"c" * 64, "d" * 64}


SDIST_LOCK = lock_text([("Uni_Path", "1.1", "e" * 64)])


def test_lock_without_removes_only_named_entries():
    text = lock_text([("keep-me", "1.0", "a" * 64), ("uni-path", "1.1", "b" * 64)])
    filtered = fw.lock_without(text, {"uni-path"})
    assert [pin.name for pin in fw.parse_lock(filtered)] == ["keep-me"]
    assert "b" * 64 not in filtered and "a" * 64 in filtered


def test_sdist_lock_parses_like_any_lock(tool):
    (tool / "artifacts").mkdir(exist_ok=True)
    (tool / "artifacts" / "requirements-sdist.lock").write_text(SDIST_LOCK, encoding="utf-8")
    pins = fw.read_sdist_pins(tool)
    assert [(pin.name, pin.version) for pin in pins] == [("uni-path", "1.1")]
    assert fw.read_sdist_pins(tool / "artifacts") == []


def test_build_sdist_command_is_reproducible_and_offline(tmp_path):
    command = fw.build_sdist_command(tmp_path / "T D", tmp_path / "out", f"img@{DIGEST}", None)
    joined = " ".join(command)
    assert "SOURCE_DATE_EPOCH=315532800" in joined
    assert "PYTHONHASHSEED=0" in joined
    assert "--no-build-isolation" in joined and "--no-index" in joined
    assert "--no-binary=:all:" in joined and "--require-hashes" in joined
    assert any(part.endswith("/in/requirements-sdist.lock:ro") for part in command)
    assert any(part.endswith("/in/requirements-build.lock:ro") for part in command)


def test_reproducibility_accepts_identical_builds():
    ok, runs = fw.check_reproducible(lambda: {"u-1.1-py3-none-any.whl": "a" * 64})
    assert ok and runs[0] == runs[1]


def test_reproducibility_rejects_differing_builds():
    shas = iter(["a" * 64, "b" * 64])
    ok, runs = fw.check_reproducible(lambda: {"u-1.1-py3-none-any.whl": next(shas)})
    assert not ok and runs[0] != runs[1]
