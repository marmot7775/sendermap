"""The listing: server.json for the MCP registry, the README line the registry checks, and
llms.txt on the site."""

import json
import re
import tomllib
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft7Validator

ROOT = Path(__file__).parent.parent
# The registry's schema of 2025-12-11, kept here so the suite never goes online.
REGISTRY_SCHEMA = Path(__file__).parent / "fixtures" / "mcp-server-2025-12-11.schema.json"
SERVER = json.loads((ROOT / "server.json").read_text())
NAME = "io.github.marmot7775/sendermap"


def test_server_json_validates_against_the_registry_schema() -> None:
    schema = json.loads(REGISTRY_SCHEMA.read_text())
    assert SERVER["$schema"] == schema["$id"]
    errors = sorted(e.message for e in Draft7Validator(schema).iter_errors(SERVER))
    assert errors == []


def test_server_json_names_the_pypi_package_started_with_the_mcp_extra() -> None:
    assert SERVER["name"] == NAME
    assert len(SERVER["description"]) < 100
    (package,) = SERVER["packages"]
    assert package["registryType"] == "pypi"
    assert package["identifier"] == "sendermap"
    assert package["runtimeHint"] == "uvx"
    assert package["transport"] == {"type": "stdio"}
    # uvx --from sendermap[mcp]==VERSION sendermap mcp
    (source,) = package["runtimeArguments"]
    assert (source["name"], source["value"]) == ("--from", f"sendermap[mcp]=={SERVER['version']}")
    assert [a["value"] for a in package["packageArguments"]] == ["mcp"]
    assert package["version"] == SERVER["version"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", SERVER["version"])
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert "mcp" in extras["optional-dependencies"]


def test_the_readme_carries_the_registry_line_as_a_comment() -> None:
    assert f"<!-- mcp-name: {NAME} -->" in (ROOT / "README.md").read_text()


async def test_the_site_serves_llms_txt_pointing_at_everything_an_agent_needs() -> None:
    pytest.importorskip("fastapi")
    from sendermap.web import app as site  # noqa: PLC0415

    transport = httpx.ASGITransport(app=site.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://site.test") as client:
        reply = await client.get("/llms.txt")
    assert reply.status_code == 200
    assert reply.headers["content-type"].startswith("text/plain")
    text = reply.text
    assert text.startswith("# Sendermap\n")
    for target in (
        "(/api/map?d=",
        "(/schema/sendermap-1.json)",
        "(/mcp)",
        "skills/sendermap/SKILL.md)",
        "#honest-limits)",
    ):
        assert target in text
    assert "—" not in text
