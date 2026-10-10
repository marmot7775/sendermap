"""A fake DNS zone, so the suite never touches the network."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest

from sendermap import catalog
from sendermap.dns import Answer, Lookups, Status, norm
from sendermap.sources import Context


class Zone:
    """Records keyed by (name, type), CNAMEs followed, "*." wildcards honoured, and names that
    fail on purpose. Anything else does not exist."""

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]] | None = None,
        cnames: dict[str, str] | None = None,
        failing: set[str] | None = None,
    ) -> None:
        self.records = {(norm(n), t): v for (n, t), v in (records or {}).items()}
        self.cnames = {norm(k): norm(v) for k, v in (cnames or {}).items()}
        self.failing = {norm(n) for n in failing or ()}
        self.asked: list[tuple[str, str]] = []

    def add(self, name: str, rtype: str, *values: str) -> Zone:
        self.records.setdefault((norm(name), rtype), []).extend(values)
        return self

    def alias(self, name: str, target: str) -> Zone:
        self.cnames[norm(name)] = norm(target)
        return self

    async def query(self, name: str, rtype: str) -> Answer:
        name = norm(name)
        self.asked.append((name, rtype))
        if name in self.failing:
            return Answer(name, rtype, Status.FAILED)
        chain: list[str] = []
        current = name
        while current in self.cnames and len(chain) < 16:
            current = self.cnames[current]
            chain.append(current)
        if rtype == "CNAME" and chain:
            return Answer(name, rtype, Status.OK, (chain[0],), tuple(chain))
        found = self._lookup(current, rtype)
        if found:
            return Answer(name, rtype, Status.OK, tuple(found), tuple(chain))
        if self._exists(current):
            return Answer(name, rtype, Status.NOANSWER, chain=tuple(chain))
        return Answer(name, rtype, Status.NXDOMAIN, chain=tuple(chain))

    def _lookup(self, name: str, rtype: str) -> list[str]:
        if (name, rtype) in self.records:
            return self.records[(name, rtype)]
        _, _, parent = name.partition(".")
        return self.records.get((f"*.{parent}", rtype), [])

    def _exists(self, name: str) -> bool:
        return any(n == name for n, _ in self.records) or name in self.cnames


CHECKED = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def context(zone: Zone, domain: str = "example.com") -> Context:
    return Context(domain, Lookups(zone), catalog.load(), CHECKED)


@pytest.fixture
async def offline() -> AsyncIterator[httpx.AsyncClient]:
    """An HTTP client with an empty certificate log that fails the test on any other request:
    the suite never goes online."""

    def refuse(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.certspotter.com":
            return httpx.Response(200, json=[])  # no certificates logged
        raise AssertionError(f"test tried to reach {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse)) as client:
        yield client
