"""DNS lookups: one small interface, two ways to answer it, and a cache in front.

Every lookup returns an Answer, never raises. A failed lookup is a status of its own, so a source
can tell "no record here" from "we could not find out" and say only what it actually learned.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.rdata
import dns.rdatatype
import dns.resolver
import httpx
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.TXT import TXT


class Status(StrEnum):
    OK = "ok"
    NXDOMAIN = "no such name"
    NOANSWER = "no record of this type"
    FAILED = "lookup failed"


@dataclass(frozen=True, slots=True)
class Answer:
    """One question's answer. A record set has no order (RFC 2181 section 5) and a resolver
    returns it in any, so `records` is sorted here, at the boundary, and the same set reads the
    same from every resolver. `chain` keeps its order, since hops are a sequence."""

    name: str
    rtype: str
    status: Status
    records: tuple[str, ...] = ()
    chain: tuple[str, ...] = ()  # the CNAME hops the name led through, in order

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", sort_records(self.rtype, self.records))

    @property
    def ok(self) -> bool:
        return self.status is Status.OK

    @property
    def answered(self) -> bool:
        """The server gave a definite answer, records or none."""
        return self.status is not Status.FAILED

    @property
    def target(self) -> str | None:
        """Where the name finally led, when it is an alias."""
        return self.chain[-1] if self.chain else None

    @property
    def dangling(self) -> bool:
        """An alias to a name that does not exist."""
        return self.status is Status.NXDOMAIN and bool(self.chain)


def sort_records(rtype: str, records: tuple[str, ...]) -> tuple[str, ...]:
    """MX by preference then host, everything else by text."""
    if rtype.upper() == "MX":
        return tuple(sorted(records, key=_mx_order))
    return tuple(sorted(records))


def _mx_order(record: str) -> tuple[int, str]:
    preference, _, host = record.partition(" ")
    # A record that is not "preference host" goes after every one that is, by its text.
    return (int(preference), host) if preference.isdigit() else (1 << 16, record)


class Resolver(Protocol):
    async def query(self, name: str, rtype: str) -> Answer: ...


def norm(name: str) -> str:
    return name.strip().lower().rstrip(".")


# ---------------------------------------------------------------- dnspython


class SystemResolver:
    """The machine's own resolver, through dnspython."""

    def __init__(self, timeout: float = 4.0, nameservers: list[str] | None = None) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers

    async def query(self, name: str, rtype: str) -> Answer:
        name = norm(name)
        try:
            result = await self._resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as e:
            return Answer(name, rtype, Status.NXDOMAIN, chain=_nx_chain(e, name))
        except (dns.resolver.NoNameservers, dns.exception.DNSException):
            return Answer(name, rtype, Status.FAILED)
        chain = _cname_chain(result.response, name)
        if result.rrset is None:
            return Answer(name, rtype, Status.NOANSWER, chain=chain)
        return Answer(name, rtype, Status.OK, tuple(_text(r) for r in result.rrset), chain)


def _text(rdata: dns.rdata.Rdata) -> str:
    if isinstance(rdata, TXT):  # one record's strings join into one value
        return "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
    if isinstance(rdata, MX):
        return f"{rdata.preference} {norm(str(rdata.exchange))}"
    return norm(str(rdata))


def _cname_chain(response: dns.message.Message, name: str) -> tuple[str, ...]:
    hops: list[str] = []
    current = name
    targets = {
        norm(str(rrset.name)): norm(str(rrset[0].target))
        for rrset in response.answer
        if rrset.rdtype == dns.rdatatype.CNAME
    }
    while current in targets and len(hops) < 16:
        current = targets[current]
        hops.append(current)
    return tuple(hops)


def _nx_chain(error: dns.resolver.NXDOMAIN, name: str) -> tuple[str, ...]:
    # The responses that ended in NXDOMAIN still carry the CNAMEs that led there.
    responses: dict[dns.name.Name, dns.message.Message] = error.responses()  # type: ignore[no-untyped-call]
    for response in responses.values():
        chain = _cname_chain(response, name)
        if chain:
            return chain
    return ()


# ---------------------------------------------------------------- DNS over HTTPS


class DohResolver:
    """Cloudflare's or Google's JSON API, for machines whose resolver cannot be trusted. Give it
    its own client from `doh_client`."""

    CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
    GOOGLE = "https://dns.google/resolve"

    def __init__(self, client: httpx.AsyncClient, endpoint: str = CLOUDFLARE) -> None:
        self._client = client
        self._endpoint = endpoint

    async def query(self, name: str, rtype: str) -> Answer:
        name = norm(name)
        try:
            response = await self._client.get(
                self._endpoint,
                params={"name": name, "type": rtype},
                headers={"accept": "application/dns-json"},
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return Answer(name, rtype, Status.FAILED)
        return parse_doh(name, rtype, body)


def doh_client() -> httpx.AsyncClient:
    """A client for DohResolver alone: a map asks hundreds of questions in a burst, and through
    one endpoint at httpx's defaults (a 5 second timeout, connections without limit) about a
    third of them time out and read as lookup failed. Eight connections and 30 seconds answer
    them all."""
    return httpx.AsyncClient(timeout=30, limits=httpx.Limits(max_connections=8))


_DOH_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}


def parse_doh(name: str, rtype: str, body: dict[str, object]) -> Answer:
    rows = [r for r in body.get("Answer") or [] if isinstance(r, dict)]  # type: ignore[attr-defined]
    chain = tuple(norm(str(r["data"])) for r in rows if r.get("type") == 5)
    want = _DOH_TYPES.get(rtype)
    records = tuple(_doh_text(rtype, str(r["data"])) for r in rows if r.get("type") == want)
    match body.get("Status"):
        case 0 if records:
            return Answer(name, rtype, Status.OK, records, chain)
        case 0:
            return Answer(name, rtype, Status.NOANSWER, chain=chain)
        case 3:
            return Answer(name, rtype, Status.NXDOMAIN, chain=chain)
        case _:
            return Answer(name, rtype, Status.FAILED)


def _doh_text(rtype: str, data: str) -> str:
    if rtype == "TXT":  # '"part one" "part two"' -> 'part onepart two'
        parts = [p for p in data.split('"')[1::2]]
        return "".join(parts) if parts else data
    if rtype == "MX":
        preference, _, host = data.partition(" ")
        return f"{preference} {norm(host)}"
    return norm(data)


# ---------------------------------------------------------------- the cache in front


class Lookups:
    """Answers each (name, type) once, however many sources ask, and counts the queries.

    Concurrent askers share one in-flight query. A semaphore keeps the burst polite.
    """

    def __init__(self, resolver: Resolver, concurrency: int = 32) -> None:
        self._resolver = resolver
        self._limit = asyncio.Semaphore(concurrency)
        self._pending: dict[tuple[str, str], asyncio.Task[Answer]] = {}
        self.count = 0

    async def query(self, name: str, rtype: str) -> Answer:
        key = (norm(name), rtype.upper())
        if key not in self._pending:
            self._pending[key] = asyncio.ensure_future(self._ask(*key))
        return await self._pending[key]

    async def _ask(self, name: str, rtype: str) -> Answer:
        async with self._limit:
            self.count += 1
            return await self._resolver.query(name, rtype)

    async def txt(self, name: str) -> Answer:
        return await self.query(name, "TXT")
