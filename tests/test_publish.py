"""The publish workflow and the release notes it takes from CHANGELOG.md."""

import importlib.util
import json
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
    assert list(jobs) == ["build", "publish", "release", "registry", "deploy"]
    build = " ".join(str(s.get("run", "")) for s in jobs["build"]["steps"])
    assert "python -m build" in build and "tools/release_notes.py" in build
    assert jobs["build"]["steps"][0]["with"]["fetch-depth"] == 0
    publish = jobs["publish"]
    assert publish["environment"]["name"] == "pypi"
    assert publish["if"] == "vars.PYPI_READY == 'true'"  # held until the variable is set
    assert publish["permissions"] == {"id-token": "write"}
    (upload,) = [s for s in publish["steps"] if "gh-action-pypi-publish" in s.get("uses", "")]
    assert upload["uses"] == "pypa/gh-action-pypi-publish@release/v1"
    assert upload["with"]["attestations"] is True
    assert jobs["release"]["needs"] == "publish"
    assert "gh release create" in jobs["release"]["steps"][-1]["run"]
    registry = jobs["registry"]
    assert registry["needs"] == "publish"  # so it is held with publishing
    assert registry["permissions"] == {"id-token": "write", "contents": "read"}
    steps = " ".join(str(s.get("run", "")) for s in registry["steps"])
    assert "mcp-publisher login github-oidc" in steps and "mcp-publisher publish" in steps
    assert "releases/download/v" in steps  # a pinned mcp-publisher, not latest
    deploy = jobs["deploy"]
    assert deploy["needs"] == "publish"  # held with publishing, so PyPI has the version
    run = deploy["steps"][-1]["run"]
    assert "secrets." not in run  # secrets reach the shell as env, never inlined
    assert run.rstrip().endswith('"${GITHUB_REF_NAME#v}"')  # the version is the only command


def test_the_workflow_says_what_holds_publishing_and_where_it_is_set() -> None:
    text = (ROOT / ".github/workflows/publish.yml").read_text()
    head = text.split("\nname:", 1)[0]
    assert "PYPI_READY" in head
    assert "Settings, Secrets and variables, Actions, Variables" in head
    readme = (ROOT / "README.md").read_text()
    assert (
        "`PYPI_READY`" in readme and "Settings, Secrets and variables, Actions, Variables" in readme
    )


def test_the_changelog_holds_the_released_version_under_unreleased() -> None:
    """The real CHANGELOG.md: the version server.json names has its notes, and Unreleased sits
    above it, open for the changes since."""
    tool = load_tool()
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    version = json.loads((ROOT / "server.json").read_text())["version"]
    notes = tool.section(changelog, f"v{version}")
    assert notes and notes.startswith("- ")
    headings = [line for line in changelog.splitlines() if line.startswith("## ")]
    assert headings[0] == "## Unreleased"
    assert headings[1].startswith(f"## {version} (")
