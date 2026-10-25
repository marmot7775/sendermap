"""The website: it starts with uvicorn's access log off, so no query string is logged, and it
shows the same View as the command line, rendered on the server."""

import asyncio
import json
import logging
import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_html import DOMAIN, hostile_map

uvicorn = pytest.importorskip("uvicorn")
pytest.importorskip("fastapi")

import sendermap  # noqa: E402
from sendermap.model import SenderMap  # noqa: E402
from sendermap.render import html, markdown  # noqa: E402
from sendermap.web import app as site  # noqa: E402


class Kept(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


async def test_the_app_starts_with_access_logging_off() -> None:
    # Uvicorn's own default is to log every request, query string included.
    config = uvicorn.Config(site.app, host="127.0.0.1", port=0, log_level="info")
    assert config.access_log
    server = uvicorn.Server(config)
    serving = asyncio.create_task(server.serve())
    kept = Kept()
    access = logging.getLogger(site.ACCESS_LOG)
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        access.addHandler(kept)
        port = server.servers[0].sockets[0].getsockname()[1]
        async with httpx.AsyncClient() as client:
            reply = await client.get(f"http://127.0.0.1:{port}/api/health?d=private.example")
        assert reply.status_code == 200
    finally:
        server.should_exit = True
        await serving
        access.removeHandler(kept)
    assert [r.getMessage() for r in kept.records] == []
    assert access.disabled


async def test_the_site_serves_the_schema() -> None:
    transport = httpx.ASGITransport(app=site.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://site.test") as client:
        reply = await client.get("/schema/sendermap-1.json")
    assert reply.status_code == 200
    assert reply.headers["content-type"].startswith("application/schema+json")
    assert reply.json() == sendermap.schema()


# ------------------------------------------------------------------ the page's view

STATIC = Path(site.__file__).parent / "static"
DROPPED = (
    "renderServices",
    "renderReporting",
    "renderClaimed",
    "renderAttention",
    "renderUnknowns",
    "renderChecked",
    "renderFootnote",
    "card",
    "setupLine",
    "groupUnknowns",
    "groupHeading",
    "CLAIMED_PARTS",
    "SETUP_WORDS",
    "NETWORK_VALUE",
    "IP_KINDS",
    "RESOLVERS",
)


@pytest.fixture
def cached() -> Iterator[SenderMap]:
    """A map already in the site's cache, so no request builds one."""
    result = hostile_map()
    site.state.cache[DOMAIN] = (time.monotonic(), result)
    site.state.seen.clear()
    yield result
    site.state.cache.pop(DOMAIN, None)
    site.state.seen.clear()


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=site.app), base_url="http://site")


def stream_events(body: str) -> dict[str, Any]:
    events = {}
    for block in body.strip().split("\n\n"):
        kind, data = block.split("\n", 1)
        events[kind.removeprefix("event: ")] = json.loads(data.removeprefix("data: "))
    return events


async def test_the_map_event_carries_the_map_and_its_html(cached: SenderMap) -> None:
    async with client() as c:
        reply = await c.get("/api/map/stream", params={"d": DOMAIN})
    done = stream_events(reply.text)["map"]
    assert set(done) == {"map", "html"}
    assert done["map"]["domain"] == DOMAIN
    assert done["html"] == html.html(cached)


async def test_the_fragment_is_served_as_html_with_the_apis_limits(cached: SenderMap) -> None:
    async with client() as c:
        reply = await c.get("/api/map.html", params={"d": DOMAIN})
        assert reply.status_code == 200
        assert reply.headers["content-type"].startswith("text/html")
        assert reply.text == html.html(cached)
        claimed = await c.get("/api/map.html", params={"d": DOMAIN, "claimed": "Klaviyo"})
        assert "Claimed senders" in claimed.text
        assert (await c.get("/api/map.html", params={"d": "not a domain"})).status_code == 422
        assert (await c.get("/api/map.html", params={"d": "a" * 254})).status_code == 422
        site.state.seen.clear()
        codes = [
            (await c.get("/api/map.html", params={"d": DOMAIN})).status_code
            for _ in range(site.REQUESTS_PER_MINUTE + 1)
        ]
    assert codes[-1] == 429 and set(codes[:-1]) == {200}


async def test_the_fallback_path_gets_the_map_and_the_fragment(cached: SenderMap) -> None:
    script = (STATIC / "app.js").read_text()
    assert "fetch(`/api/map?${query(domain)}`)" in script
    assert "fetch(`/api/map.html?${query(domain)}`)" in script
    async with client() as c:
        mapped = (await c.get("/api/map", params={"d": DOMAIN})).json()
        page = (await c.get("/api/map.html", params={"d": DOMAIN})).text
        md = (await c.get("/api/map.md", params={"d": DOMAIN})).text
    assert mapped == json.loads(json.dumps(cached.to_dict(), default=str))
    assert page == html.html(cached)
    assert md == markdown.render(cached)


def test_the_page_holds_no_copy_of_the_views_logic() -> None:
    script = re.sub(r"//.*", "", (STATIC / "app.js").read_text())
    for name in DROPPED:
        assert not re.search(rf"\b{name}\b", script), name
    assert "view.innerHTML = fragment" in script
    page = (STATIC / "index.html").read_text()
    for gone in (
        "services",
        "reporting",
        "claimed",
        "attention",
        "unknowns",
        "checked",
        "footnote",
    ):
        assert f'id="{gone}"' not in page
    assert 'id="view"' in page


async def test_the_page_links_its_assets_by_version() -> None:
    async with client() as c:
        page = (await c.get("/")).text
    for asset in site.ASSETS:
        assert f'"{asset}?v={sendermap.__version__}"' in page
        assert f'"{asset}"' not in page
