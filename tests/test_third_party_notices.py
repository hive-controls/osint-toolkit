"""Tests for shared/build/gen_third_party_notices.py using fixture wheels built with zipfile."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR_PATH = REPO_ROOT / "shared" / "build" / "gen_third_party_notices.py"

spec = importlib.util.spec_from_file_location("gen_third_party_notices", GENERATOR_PATH)
generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generator
spec.loader.exec_module(generator)

MIT_TEXT = "MIT License\n\nPermission is hereby granted.\n"


def build_wheel(
    wheelhouse: Path,
    name: str,
    version: str,
    metadata_headers: list[str] | None = None,
    files: dict[str, str] | None = None,
) -> tuple[Path, str]:
    wheelhouse.mkdir(parents=True, exist_ok=True)
    path = wheelhouse / f"{name}-{version}-py3-none-any.whl"
    headers = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"] + (metadata_headers or [])
    dist_info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{dist_info}/METADATA", "\n".join(headers) + "\n\nbody\n")
        for member, text in (files or {}).items():
            archive.writestr(f"{dist_info}/{member}", text)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def write_lock(path: Path, pins: list[tuple[str, str, str]]) -> None:
    body = "# header\n"
    for name, version, digest in pins:
        body += f"{name}=={version} \\\n    --hash=sha256:{digest}\n"
    path.write_text(body, encoding="utf-8")


def make_tool(tmp_path: Path, packages: list[dict]) -> tuple[Path, Path, Path]:
    root = tmp_path / "root"
    wheelhouse = root / "Tool" / "artifacts" / "wheelhouse"
    pins = []
    for package in packages:
        _path, digest = build_wheel(
            wheelhouse, package["name"], package["version"], package.get("headers"), package.get("files")
        )
        pins.append((package["name"], package["version"], digest))
    lock = root / "Tool" / "requirements.lock"
    write_lock(lock, pins)
    return root, lock, wheelhouse


def generate(root: Path, lock: Path, wheelhouse: Path, trimmed: list[str] | None = None) -> str:
    overrides = generator.load_overrides(root)
    return generator.generate_tool_notice("Tool", lock, wheelhouse, overrides, root, trimmed or [])


def test_license_expression_wins(tmp_path):
    root, lock, wheelhouse = make_tool(
        tmp_path, [{"name": "alpha", "version": "1.0", "headers": ["License-Expression: Apache-2.0", "License: Other"]}]
    )
    output = generate(root, lock, wheelhouse)
    assert "| alpha | 1.0 | Apache-2.0 | License-Expression |" in output


def test_license_field_used_when_short_and_known(tmp_path):
    root, lock, wheelhouse = make_tool(
        tmp_path, [{"name": "alpha", "version": "1.0", "headers": ["License: BSD-3-Clause"]}]
    )
    assert "| alpha | 1.0 | BSD-3-Clause | License field |" in generate(root, lock, wheelhouse)


def test_unknown_or_long_license_field_falls_through_to_classifier(tmp_path):
    headers = ["License: UNKNOWN", "Classifier: License :: OSI Approved :: ISC License (ISCL)"]
    root, lock, wheelhouse = make_tool(tmp_path, [{"name": "alpha", "version": "1.0", "headers": headers}])
    assert "| alpha | 1.0 | ISC License (ISCL) | trove classifier |" in generate(root, lock, wheelhouse)


def test_license_file_first_line_and_verbatim_text(tmp_path):
    root, lock, wheelhouse = make_tool(
        tmp_path, [{"name": "alpha", "version": "1.0", "files": {"licenses/LICENSE": MIT_TEXT}}]
    )
    output = generate(root, lock, wheelhouse)
    assert "| alpha | 1.0 | MIT License | license file first line |" in output
    assert MIT_TEXT.rstrip("\n") in output


def test_no_license_and_no_override_is_unknown_error(tmp_path):
    root, lock, wheelhouse = make_tool(tmp_path, [{"name": "alpha", "version": "1.0"}])
    with pytest.raises(generator.UnknownLicenseError):
        generate(root, lock, wheelhouse)


def test_main_exits_nonzero_for_unknown_license(tmp_path):
    root = tmp_path / "root"
    wheelhouse = root / "Maigret Docker" / "artifacts" / "wheelhouse"
    _path, digest = build_wheel(wheelhouse, "alpha", "1.0")
    write_lock(root / "Maigret Docker" / "requirements.lock", [("alpha", "1.0", digest)])
    code = generator.main(["--root", str(root), "--tool", "Maigret Docker"])
    assert code == generator.EXIT_UNKNOWN_LICENSE
    assert not (root / "Maigret Docker" / "THIRD-PARTY-NOTICES.md").exists()


def write_override(root: Path, entry: dict, texts: dict[str, str] | None = None) -> None:
    (root / "shared" / "build" / "license-texts").mkdir(parents=True)
    for file_name, text in (texts or {}).items():
        (root / "shared" / "build" / "license-texts" / file_name).write_bytes(text.encode("utf-8"))
    payload = {"overrides": {"alpha==1.0": entry}}
    (root / "shared" / "build" / "license-overrides.json").write_text(json.dumps(payload), encoding="utf-8")


def test_override_with_text_resolves_unknown_license(tmp_path):
    root, lock, wheelhouse = make_tool(tmp_path, [{"name": "alpha", "version": "1.0"}])
    text = "Custom license text\n"
    entry = {
        "spdx": "MIT",
        "texts": [{"path": "alpha.txt", "url": "https://example.invalid/L", "sha256": hashlib.sha256(text.encode()).hexdigest()}],
    }
    write_override(root, entry, {"alpha.txt": text})
    output = generate(root, lock, wheelhouse)
    assert "| alpha | 1.0 | MIT | override |" in output
    assert "Custom license text" in output
    assert "https://example.invalid/L" in output


def test_pending_override_fails_loudly(tmp_path):
    root, lock, wheelhouse = make_tool(tmp_path, [{"name": "alpha", "version": "1.0"}])
    write_override(root, {"spdx": "MIT", "status": "pending"})
    with pytest.raises(generator.UnknownLicenseError):
        generate(root, lock, wheelhouse)


def test_override_text_hash_mismatch_is_refused(tmp_path):
    root, lock, wheelhouse = make_tool(tmp_path, [{"name": "alpha", "version": "1.0"}])
    entry = {"spdx": "MIT", "texts": [{"path": "alpha.txt", "url": "u", "sha256": "0" * 64}]}
    write_override(root, entry, {"alpha.txt": "text\n"})
    with pytest.raises(generator.RefusedError):
        generate(root, lock, wheelhouse)


def test_sha_mismatch_is_refused(tmp_path):
    root, lock, wheelhouse = make_tool(
        tmp_path, [{"name": "alpha", "version": "1.0", "headers": ["License-Expression: MIT"]}]
    )
    write_lock(lock, [("alpha", "1.0", "f" * 64)])
    with pytest.raises(generator.RefusedError, match="sha256 mismatch"):
        generate(root, lock, wheelhouse)


def test_missing_and_extra_wheels_are_refused(tmp_path):
    root, lock, wheelhouse = make_tool(
        tmp_path, [{"name": "alpha", "version": "1.0", "headers": ["License-Expression: MIT"]}]
    )
    build_wheel(wheelhouse, "extra", "2.0", ["License-Expression: MIT"])
    with pytest.raises(generator.RefusedError, match="extra wheel"):
        generate(root, lock, wheelhouse)
    for wheel in wheelhouse.glob("alpha*"):
        wheel.unlink()
    with pytest.raises(generator.RefusedError, match="missing wheel"):
        generate(root, lock, wheelhouse)


def test_trimmed_packages_listed_as_build_time_only(tmp_path):
    packages = [
        {"name": "alpha", "version": "1.0", "headers": ["License-Expression: MIT"], "files": {"LICENSE": MIT_TEXT}},
        {"name": "builder", "version": "2.0", "headers": ["License-Expression: GPL-2.0-or-later"], "files": {"LICENSE": "GPL BUILDER TEXT\n"}},
    ]
    root, lock, wheelhouse = make_tool(tmp_path, packages)
    output = generate(root, lock, wheelhouse, trimmed=["builder"])
    runtime, build_only = output.split("## Build-time only — removed from the runtime image")
    assert "| alpha | 1.0 |" in runtime
    assert "| builder | 2.0 | GPL-2.0-or-later |" in build_only
    assert "GPL BUILDER TEXT" not in output
    assert "| builder |" not in runtime


def test_trimmed_name_not_in_lock_is_refused(tmp_path):
    root, lock, wheelhouse = make_tool(
        tmp_path, [{"name": "alpha", "version": "1.0", "headers": ["License-Expression: MIT"]}]
    )
    with pytest.raises(generator.RefusedError, match="trimmed"):
        generate(root, lock, wheelhouse, trimmed=["ghost"])


def test_output_is_deterministic_and_sorted(tmp_path):
    names = ["zeta", "beta", "mu", "alpha", "omega", "gamma", "delta"]
    packages = [{"name": n, "version": "1.0", "headers": ["License-Expression: MIT"], "files": {"LICENSE": f"{n} text\n"}} for n in names]
    root, lock, wheelhouse = make_tool(tmp_path, packages)
    first = generate(root, lock, wheelhouse)
    second = generate(root, lock, wheelhouse)
    assert first == second
    table_order = re.findall(r"^\| (\w+) \| 1\.0 \| MIT \|", first, re.MULTILINE)
    assert table_order == sorted(names)
    section_order = re.findall(r"^### (\w+) 1\.0$", first, re.MULTILINE)
    assert section_order == sorted(names)


def test_header_names_tool_lock_count_and_generator_version(tmp_path):
    root, lock, wheelhouse = make_tool(
        tmp_path, [{"name": "alpha", "version": "1.0", "headers": ["License-Expression: MIT"]}]
    )
    output = generate(root, lock, wheelhouse)
    assert "- Tool: Tool" in output
    assert "- Pinned packages: 1" in output
    assert f"v{generator.GENERATOR_VERSION}" in output


@pytest.mark.parametrize("tool", sorted(generator.TOOL_TRIMMED))
def test_committed_notices_match_generated(tool):
    wheelhouse = REPO_ROOT / tool / "artifacts" / "wheelhouse"
    if not any(wheelhouse.glob("*.whl")):
        pytest.skip("wheelhouse not fetched; run shared/build/fetch_wheelhouse.py")
    assert generator.main(["--root", str(REPO_ROOT), "--tool", tool, "--check"]) == 0
