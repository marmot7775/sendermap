"""The package: its version comes from the installed metadata (the git tag at build time), it is
marked as typed, the development tools are a dependency group rather than an extra, and the
changelog has an Unreleased section for the next release to take."""

import tomllib
from importlib import metadata, resources
from pathlib import Path

import sendermap

ROOT = Path(__file__).parent.parent


def test_the_version_is_the_installed_packages() -> None:
    assert sendermap.__version__ == metadata.version("sendermap")
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "version" in pyproject["project"]["dynamic"]
    assert pyproject["tool"]["hatch"]["version"] == {"source": "vcs", "fallback-version": "0.0.0"}


def test_the_package_is_typed() -> None:
    assert resources.files("sendermap").joinpath("py.typed").is_file()


def test_development_tools_are_a_group_and_web_and_mcp_the_only_extras() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert list(pyproject["project"]["optional-dependencies"]) == ["web", "mcp"]
    assert any(d.startswith("pytest") for d in pyproject["dependency-groups"]["dev"])
    assert (ROOT / "uv.lock").is_file()


def test_the_changelog_keeps_an_unreleased_section() -> None:
    assert "\n## Unreleased\n" in (ROOT / "CHANGELOG.md").read_text()
