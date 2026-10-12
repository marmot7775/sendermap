"""The website: it starts with uvicorn's access log off, so no query string is logged."""

import asyncio
import logging

import httpx
import pytest

uvicorn = pytest.importorskip("uvicorn")
pytest.importorskip("fastapi")

import sendermap  # noqa: E402
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
