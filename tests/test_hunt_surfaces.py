"""The 2026-11 hunt fixes say the same on every surface: the command line, the website's API
and the MCP tool all map faß.de as xn--fa-hia.de (IDNA 2008), and all carry the SPF /0 risk and
the unauthorized DMARC report address."""

import importlib
import json
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone

from sendermap import cli, map_domain
from sendermap.model import SenderMap

DOMAIN = "xn--fa-hia.de"  # faß.de, as IDNA 2008 encodes it; IDNA 2003 gave fass.de
SPF_RISK = f"SPF at {DOMAIN} authorizes every IPv4 server"
REPORTS = f"DMARC reports for {DOMAIN} to reports.example.net are not authorized"


def zone() -> Zone:
    return (
        Zone()
        .add(DOMAIN, "TXT", "v=spf1 ip4:0.0.0.0/0 -all")
        .add(DOMAIN, "MX", "0 .")
        .add(f"_dmarc.{DOMAIN}", "TXT", "v=DMARC1; p=none; rua=mailto:r@reports.example.net")
        # The IDNA 2003 name publishes something else, so mapping it would show.
        .add("fass.de", "TXT", "v=spf1 -all")
    )


def titles(data: dict[str, Any]) -> list[str]:
    return [f["title"] for f in data["findings"]]


def test_the_command_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "SystemResolver", zone)
    out = tmp_path / "map.json"
    flags = ["--no-web", "--no-subdomains", "--json", "--output", str(out)]
    assert cli.main(["faß.de", *flags]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["domain"] == DOMAIN
    assert {SPF_RISK, REPORTS} <= set(titles(data))
    assert cli.main(["faß.de", "--no-web", "--no-subdomains"]) == 0
    printed = " ".join(capsys.readouterr().out.split())
    assert SPF_RISK in printed and REPORTS in printed


@pytest.fixture
def site(monkeypatch: pytest.MonkeyPatch) -> Iterator[ModuleType]:
    pytest.importorskip("fastapi")
    app = importlib.import_module("sendermap.web.app")

    async def build(domain: str, **kwargs: Any) -> SenderMap:
        kwargs.pop("http", None)
        return await map_domain(
            domain, resolver=zone(), use_web=False, use_subdomains=False, **kwargs
        )

    monkeypatch.setattr(app, "map_domain", build)
    for held in (app.state.cache, app.state.running, app.state.seen, app.state.built):
        held.clear()
    yield app
    for held in (app.state.cache, app.state.running, app.state.seen, app.state.built):
        held.clear()


async def test_the_website(site: ModuleType) -> None:
    transport = httpx.ASGITransport(app=site.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://site.test") as client:
        data = (await client.get("/api/map", params={"d": "faß.de"})).json()
        page = (await client.get("/api/map.md", params={"d": "faß.de"})).text
    assert data["domain"] == DOMAIN
    assert {SPF_RISK, REPORTS} <= set(titles(data))
    assert SPF_RISK in page and REPORTS in page


async def test_the_mcp_tool() -> None:
    pytest.importorskip("fastmcp")
    from fastmcp import Client  # noqa: PLC0415

    from sendermap import mcp_server  # noqa: PLC0415

    async def build(domain: str, options: Any, progress: Any) -> SenderMap:
        return await map_domain(
            domain, checked_at=CHECKED, resolver=zone(), use_web=False, use_subdomains=False
        )

    async with Client(mcp_server.create(build)) as client:
        result = await client.call_tool("sendermap_map", {"domain": "faß.de"})
    data = result.structured_content
    assert data is not None
    assert data["domain"] == DOMAIN
    assert {SPF_RISK, REPORTS} <= set(titles(data))
    text = result.content[0].text
    assert SPF_RISK in text and REPORTS in text
