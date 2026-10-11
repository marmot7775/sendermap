"""The Sendermap website: one page, and an API that streams a map as it is built.

Privacy: the server keeps no record of the domains looked up. Uvicorn's access log, which would
record each request's query string, is turned off when the app starts. Results are held in
memory for ten minutes so a shared link opens instantly, and a visitor's address is held in
memory for one minute for the rate limit. Neither is written anywhere. The claimed names a
request carries are used for its response only: the cached map does not hold them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .. import __version__, catalog
from ..engine import Progress, clean_domain, map_domain
from ..model import SenderMap
from ..reconcile import split, with_claimed
from ..render import markdown

ACCESS_LOG = "uvicorn.access"
CACHE_SECONDS = 600
MAX_RUNNING = 6
REQUESTS_PER_MINUTE = 12
STATIC = resources.files(__package__).joinpath("static")


@dataclass
class _State:
    http: httpx.AsyncClient | None = None
    cache: dict[str, tuple[float, SenderMap]] = field(default_factory=dict)
    running: dict[str, asyncio.Task[SenderMap]] = field(default_factory=dict)
    slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(MAX_RUNNING))
    seen: dict[str, list[float]] = field(default_factory=dict)


state = _State()


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Uvicorn has configured its loggers by now; turning this one off keeps ?d= out of any log,
    # whatever flags the server was started with.
    logging.getLogger(ACCESS_LOG).disabled = True
    async with httpx.AsyncClient() as http:
        state.http = http
        yield


app = FastAPI(title="Sendermap", version=__version__, lifespan=_lifespan, docs_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index() -> FileResponse:
    return FileResponse(str(STATIC.joinpath("index.html")))


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


# The services the domain's owner says they use, comma separated: the map's reconciliation.
CLAIMED = Query("", max_length=2000)


@app.get("/api/map")
async def get_map(
    request: Request, d: str = Query(..., max_length=253), claimed: str = CLAIMED
) -> dict[str, object]:
    domain = _domain(d)
    _limit(request)
    return (await _map(domain, _ignore, claimed)).to_dict()


@app.get("/api/map.md", response_class=PlainTextResponse)
async def get_markdown(
    request: Request, d: str = Query(..., max_length=253), claimed: str = CLAIMED
) -> str:
    domain = _domain(d)
    _limit(request)
    return markdown.render(await _map(domain, _ignore, claimed))


@app.get("/api/map/stream")
async def stream(
    request: Request, d: str = Query(..., max_length=253), claimed: str = CLAIMED
) -> StreamingResponse:
    """Server-sent events: `progress` lines while the map builds, then one `map` event."""
    domain = _domain(d)
    _limit(request)
    queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue()

    async def progress(step: str) -> None:
        await queue.put(("progress", json.dumps({"step": step})))

    async def build() -> None:
        try:
            result = await _map(domain, progress, claimed)
            await queue.put(("map", json.dumps(result.to_dict(), default=str)))
        except Exception:  # the page shows a plain error instead of hanging
            await queue.put(("failed", json.dumps({"error": "The map could not be built."})))

    async def events() -> AsyncIterator[str]:
        task = asyncio.create_task(build())
        try:
            while True:
                kind, data = await queue.get()
                yield f"event: {kind}\ndata: {data}\n\n"
                if kind in ("map", "failed"):
                    break
        finally:
            if not task.done():
                task.cancel()

    headers = {"cache-control": "no-store", "x-accel-buffering": "no"}
    return StreamingResponse(events(), media_type="text/event-stream", headers=headers)


async def _map(domain: str, progress: Progress, claimed: str) -> SenderMap:
    """The map from the cache or one shared build, then reconciled with this request's claimed
    names, which are never cached or kept."""
    return with_claimed(await _shared(domain, progress), split(claimed), catalog.load())


async def _shared(domain: str, progress: Progress) -> SenderMap:
    cached = state.cache.get(domain)
    if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
        await progress("Done")
        return cached[1]
    if domain not in state.running:  # one build per domain, however many visitors ask
        state.running[domain] = asyncio.create_task(_build(domain, progress))
    try:
        return await asyncio.shield(state.running[domain])
    finally:
        if state.running.get(domain) and state.running[domain].done():
            state.running.pop(domain, None)


async def _build(domain: str, progress: Progress) -> SenderMap:
    async with state.slots:
        result = await map_domain(
            domain, checked_at=datetime.now(UTC), http=state.http, progress=progress
        )
    state.cache[domain] = (time.monotonic(), result)
    for old in [d for d, (at, _) in state.cache.items() if time.monotonic() - at > CACHE_SECONDS]:
        del state.cache[old]
    return result


def _domain(text: str) -> str:
    try:
        return clean_domain(text)
    except ValueError as e:
        raise HTTPException(422, "That does not look like a domain.") from e


def _limit(request: Request) -> None:
    """A short sliding window per visitor. The address is held in memory for one minute and
    written nowhere."""
    who = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "")
    now = time.monotonic()
    recent = [t for t in state.seen.get(who, []) if now - t < 60]
    if len(recent) >= REQUESTS_PER_MINUTE:
        raise HTTPException(429, "Too many maps in a minute. Try again shortly.")
    state.seen[who] = [*recent, now]
    if len(state.seen) > 10_000:
        state.seen = {k: v for k, v in state.seen.items() if v and now - v[-1] < 60}


async def _ignore(_: str) -> None:
    return None
