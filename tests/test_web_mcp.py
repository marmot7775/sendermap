"""The website mounts the MCP server at /mcp over streamable HTTP: stateless, answering only for
the hosts it is told, and held to the API's limits per visitor and per target domain."""

import asyncio
import json
import time
from collections.abc import AsyncIterator

import httpx
import pytest
from test_reconcile import DOMAIN, fake_map

uvicorn = pytest.importorskip("uvicorn")
pytest.importorskip("fastapi")
pytest.importorskip("fastmcp")

from fastmcp import Client  # noqa: E402
from fastmcp.client.transports import StreamableHttpTransport  # noqa: E402
from fastmcp.exceptions import ToolError  # noqa: E402

from sendermap.web import app as site  # noqa: E402


@pytest.fixture
async def served() -> AsyncIterator[str]:
    """The site on a loopback port, its cache holding the fake map and its limits clear."""
    site.state.cache[DOMAIN] = (time.monotonic(), fake_map())
    site.state.seen.clear()
    site.state.built.clear()
    server = uvicorn.Server(uvicorn.Config(site.app, host="127.0.0.1", port=0, log_level="error"))
    serving = asyncio.create_task(server.serve())
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    finally:
        server.should_exit = True
        await serving
        site.state.cache.pop(DOMAIN, None)
        site.state.seen.clear()
        site.state.built.clear()


async def test_the_mcp_endpoint_lists_both_tools_and_maps_from_the_cache(served: str) -> None:
    async with Client(StreamableHttpTransport(f"{served}/mcp")) as client:
        tools = {t.name for t in await client.list_tools()}
        result = await client.call_tool("sendermap_map", {"domain": DOMAIN, "detail": "full"})
    assert tools == {"sendermap_map", "sendermap_vendor"}
    assert result.structured_content == json.loads(json.dumps(fake_map().to_dict(), default=str))
    assert site.state.built == {}  # the cached map, so no build was counted


async def test_the_site_still_serves_its_own_routes(served: str) -> None:
    async with httpx.AsyncClient(base_url=served) as client:
        assert (await client.get("/api/health")).status_code == 200
        assert (await client.get("/schema/sendermap-1.json")).status_code == 200
        assert (await client.get("/nothing-here")).status_code == 404


async def test_a_host_not_named_is_refused(served: str) -> None:
    async with httpx.AsyncClient(base_url=served) as client:
        reply = await client.post(
            "/mcp",
            headers={"host": "sendermap.example", "accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    assert reply.status_code == 421


def test_the_hosts_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(site.MCP_HOSTS, " sendermap.dev, www.sendermap.dev ,")
    assert site.mcp_hosts() == ["sendermap.dev", "www.sendermap.dev"]
    monkeypatch.delenv(site.MCP_HOSTS)
    assert site.mcp_hosts() == []


async def test_a_visitor_over_the_limit_gets_a_tool_error(served: str) -> None:
    site.state.seen["127.0.0.1"] = [time.monotonic()] * site.REQUESTS_PER_MINUTE
    async with Client(StreamableHttpTransport(f"{served}/mcp")) as client:
        with pytest.raises(ToolError, match="Too many maps in a minute"):
            await client.call_tool("sendermap_map", {"domain": DOMAIN})


async def test_a_target_domain_over_the_limit_gets_a_tool_error(served: str) -> None:
    # Options other than the defaults always build, so they count against the target domain.
    site.state.built[DOMAIN] = [time.monotonic()] * site.DOMAIN_BUILDS_PER_MINUTE
    async with Client(StreamableHttpTransport(f"{served}/mcp")) as client:
        with pytest.raises(ToolError, match="mapped too often"):
            await client.call_tool("sendermap_map", {"domain": DOMAIN, "website": False})


async def test_the_api_keeps_the_target_domain_limit_too() -> None:
    site.state.seen.clear()
    site.state.built["busy.test"] = [time.monotonic()] * site.DOMAIN_BUILDS_PER_MINUTE
    transport = httpx.ASGITransport(app=site.app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://site") as client:
            reply = await client.get("/api/map", params={"d": "busy.test"})
    finally:
        site.state.built.clear()
        site.state.seen.clear()
    assert reply.status_code == 429
    assert reply.json() == {
        "detail": "busy.test was mapped too often this minute. Try again shortly."
    }
