"""The publish workflow and the release notes it takes from CHANGELOG.md."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

ROOT = Path(__file__).parent.parent
CHANGELOG = """# Changelog

## Unreleased

- Next thing.

## 0.2.0 (2026-11-01)

- Second.
- Third.

## 0.1.0

- First.
"""


def load_tool() -> ModuleType:
    path = ROOT / "tools" / "release_notes.py"
    spec = importlib.util.spec_from_file_location("release_notes", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_notes_are_the_tags_section() -> None:
    tool = load_tool()
    assert tool.section(CHANGELOG, "v0.2.0") == "- Second.\n- Third."
    assert tool.section(CHANGELOG, "0.1.0") == "- First."
    assert tool.section(CHANGELOG, "v0.3.0") is None
    assert tool.section(CHANGELOG, "0.1") is None  # a prefix is not a version


def test_a_tag_without_notes_fails(tmp_path: Path) -> None:
    tool = load_tool()
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG, encoding="utf-8")
    assert tool.main(["v0.2.0", str(changelog)]) == 0
    assert tool.main(["v9.9.9", str(changelog)]) == 1


def test_the_workflow_publishes_a_tag_by_trusted_publishing() -> None:
    flow: dict[Any, Any] = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text())
    assert flow[True] == {"push": {"tags": ["v*"]}}  # YAML reads the key "on" as True
    jobs = flow["jobs"]
    assert list(jobs) == ["build", "publish", "release"]
    build = " ".join(str(s.get("run", "")) for s in jobs["build"]["steps"])
    assert "python -m build" in build and "tools/release_notes.py" in build
    assert jobs["build"]["steps"][0]["with"]["fetch-depth"] == 0
    publish = jobs["publish"]
    assert publish["environment"]["name"] == "pypi"
    assert publish["permissions"] == {"id-token": "write"}
    (upload,) = [s for s in publish["steps"] if "gh-action-pypi-publish" in s.get("uses", "")]
    assert upload["uses"] == "pypa/gh-action-pypi-publish@release/v1"
    assert upload["with"]["attestations"] is True
    assert jobs["release"]["needs"] == "publish"
    assert "gh release create" in jobs["release"]["steps"][-1]["run"]
