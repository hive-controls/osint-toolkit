"""The shipped .formic manifests are generated from shared/catalog/tools.json; any drift is a failure."""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR_PATH = REPO_ROOT / "shared" / "build" / "generate_formic.py"
GENERATED_FILES = [
    ".formic/toolkit.yaml",
    ".formic/profile.yaml",
    ".formic/tools/maigret.yaml",
    ".formic/tools/user-scanner.yaml",
    ".formic/tools/phone-lookup.yaml",
    ".formic/tools/torbot.yaml",
    ".formic/tools/osint-case.yaml",
]

spec = importlib.util.spec_from_file_location("generate_formic", GENERATOR_PATH)
generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generator
spec.loader.exec_module(generator)


def load_catalog(root: Path = REPO_ROOT) -> dict:
    return json.loads((root / "shared" / "catalog" / "tools.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("relative", GENERATED_FILES)
def test_generated_file_matches_committed(relative):
    generated = generator.generate(load_catalog())
    assert relative in generated
    assert generated[relative].encode("utf-8") == (REPO_ROOT / relative).read_bytes(), f"{relative} drifted; run: python shared/build/generate_formic.py"


def test_generator_emits_exactly_the_seven_files():
    assert sorted(generator.generate(load_catalog())) == sorted(GENERATED_FILES)


def test_every_catalog_tool_is_in_the_profile_including_torbot():
    profile = (REPO_ROOT / ".formic" / "profile.yaml").read_text(encoding="utf-8")
    listed = re.findall(r"^  ([a-z0-9-]+):$", profile, re.MULTILINE)
    catalog_ids = [tool["id"] for tool in load_catalog()["tools"]]
    assert "torbot" in listed
    assert sorted(listed) == sorted(catalog_ids)
    for tool_id in catalog_ids:
        assert (REPO_ROOT / ".formic" / "tools" / f"{tool_id}.yaml").is_file()


def test_only_catalog_tools_are_generated_or_listed():
    catalog_ids = {tool["id"] for tool in load_catalog()["tools"]}
    generated_tools = {Path(name).stem for name in generator.generate(load_catalog()) if name.startswith(".formic/tools/")}
    assert generated_tools == catalog_ids
    profile = (REPO_ROOT / ".formic" / "profile.yaml").read_text(encoding="utf-8")
    assert set(re.findall(r"^  ([a-z0-9-]+):$", profile, re.MULTILINE)) == catalog_ids


def test_generated_manifests_use_repo_relative_paths_only():
    absolute = re.compile(r"[A-Za-z]:[\\/]|\\\\|(?<![\w{}])/(?:Users|home|c|mnt)/", re.IGNORECASE)
    for relative in GENERATED_FILES:
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert not absolute.search(text), relative
        for line in text.splitlines():
            if "-File" in line or "cwd" in line:
                continue
            for path in re.findall(r'"\{repo\}/([^"]+)"', line):
                assert not path.startswith("/"), relative


def test_check_mode_reports_clean_tree_and_detects_drift(tmp_path):
    for relative in GENERATED_FILES + ["shared/catalog/tools.json"]:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / relative, target)
    assert generator.check(tmp_path) == []
    (tmp_path / ".formic" / "profile.yaml").write_text("tools: {}\n", encoding="utf-8")
    assert generator.check(tmp_path) == [".formic/profile.yaml"]


@pytest.mark.parametrize("mutation", ["title", "version", "menu", "description", "toolkit"])
def test_catalog_change_makes_generated_output_differ(mutation):
    catalog = load_catalog()
    maigret = catalog["tools"][0]
    if mutation == "title":
        maigret["formic"]["title"] += " changed"
    elif mutation == "version":
        maigret["version"] = "9.9.9"
    elif mutation == "menu":
        maigret["menu"] = "Maigret Docker/other-menu.ps1"
    elif mutation == "description":
        maigret["formic"]["description"] += " Changed."
    else:
        catalog["toolkit"]["title"] = "Changed toolkit"
    changed = generator.generate(catalog)
    committed = {name: (REPO_ROOT / name).read_text(encoding="utf-8") for name in GENERATED_FILES}
    assert changed != committed


def test_unsafe_plain_scalar_is_refused():
    catalog = load_catalog()
    catalog["tools"][0]["formic"]["description"] = "bad: scalar"
    with pytest.raises(ValueError):
        generator.generate(catalog)
