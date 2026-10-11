"""Hunt for proofs of the pending vendor patterns on customer domains.

A vendor's own domain rarely publishes what it asks its customers to publish, so most patterns in
vendors_pending.json cannot be proven there. This tool looks for them on a list of domains, one
per line in rank order, by default data/hunt_domains.txt (the top of the Tranco list). For each
domain it reads what the engine reads:

- SPF at the domain and at each sending subdomain, following every include and redirect down the
  whole chain, so a pattern included by an include counts, with that include's record as proof;
- MX at the same names, and NS at each sending label, for delegations to a service;
- DKIM keys at every selector name, proven, pending and generic, under the domain, and at each
  sending subdomain at the first SUBDOMAIN_PROBES pending names, those of the vendors its own SPF
  or MX shows first; a name under a wildcard (a key at a name nobody publishes) proves nothing;
- CNAMEs at the bounce and tracking labels the engine probes, a bounce pattern only at a bounce
  label and a tracking pattern only at a tracking label, and none through a wildcard CNAME;
- report addresses in DMARC and TLS-RPT, and verification tokens at the domain;
- the network that announces the addresses of the domain, www, mail and each sending subdomain;
- the homepage, fetched once, for website hosts and subprocessor names.

A record that may show a pending pattern is then checked with the check tools/verify_proofs.py
defines for that kind of pattern, so found means the same thing in both places. Sending
subdomains are the engine's: the sending labels that publish SPF or MX, the first MAX_SUBDOMAINS
in alphabetical order.

Domains run in parallel; the queries for one domain run one at a time. Every DNS answer and every
page is kept in a cache on disk, so a rerun asks again only what failed.

Each pending pattern found takes the highest ranked domain that showed it as its proof, dated the
day its record was read. The report on stdout lists the patterns proven, with their domain, the
patterns still pending, counts of each, and the domains that answered nothing at all. With
--move, every proven pattern moves from vendors_pending.json to vendors.json with its proof (a
selectors entry once all its names are proven); a pending block keeps the rest, and goes once
it is empty.

Usage: python tools/hunt_proofs.py [DOMAINS] [--cache DIR] [--parallel N] [--nameserver IP]
       [--doh] [--move]
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sqlite3
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import httpx
from verify_proofs import CHECKS, TIMEOUT, Checker, Seen, _page, _under

from sendermap import catalog
from sendermap.catalog import PATTERN_FIELDS, Catalog
from sendermap.dns import (
    Answer,
    DohResolver,
    Resolver,
    Status,
    SystemResolver,
    doh_client,
    norm,
)
from sendermap.engine import MAX_SUBDOMAINS, SUBDOMAIN_PROBES
from sendermap.proofs import Proof
from sendermap.sources import CANARY, networks
from sendermap.sources.spf import MAX_DEPTH, spf_records, terms

ROOT = Path(__file__).resolve().parent.parent
DOMAINS = ROOT / "data" / "hunt_domains.txt"
VENDORS = ROOT / "sendermap" / "data" / "vendors.json"
PENDING = ROOT / "sendermap" / "data" / "vendors_pending.json"
CACHE = Path.home() / ".cache" / "sendermap" / "hunt"
PARALLEL = 48
MAX_BODY = 5_000_000  # bytes of a page kept in the cache
# Second-level labels under which a registry sells names: example.co.uk is a zone of its own.
_SECOND_LEVEL = frozenset({"ac", "co", "com", "edu", "gov", "net", "org"})


@dataclass(frozen=True, slots=True, order=True)
class Wanted:
    """One pending pattern: for a selector, one of its names."""

    vendor: str
    field: str
    value: str


@dataclass(frozen=True, slots=True)
class Found:
    """A pending pattern seen on a hunted domain: where the hunt was (its rank, from 1) and the
    proof, with what the record showed."""

    wanted: Wanted
    rank: int
    hunted: str
    proof: Proof
    observed: str
    # For a selector: whether the domain shows its vendor anywhere besides the key's name.
    backed: bool = True


@dataclass(slots=True)
class Hunt:
    """What one domain showed."""

    rank: int
    domain: str
    found: list[Found] = field(default_factory=list)
    answered: bool = False


# ---------------------------------------------------------------- the cache on disk


class Cache:
    """DNS answers and pages, with the day each was read. A failed lookup and a request that
    raised are not kept, so a rerun asks them again."""

    def __init__(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path / "cache.sqlite3")
        self.writes = 0
        self.db.execute("pragma journal_mode=wal")
        self.db.execute(
            "create table if not exists dns (name text, rtype text, status text, records text,"
            " chain text, day text, primary key (name, rtype))"
        )
        self.db.execute(
            "create table if not exists http (url text primary key, status integer,"
            " headers text, body blob, day text)"
        )

    def answer(self, name: str, rtype: str) -> Answer | None:
        row = self.db.execute(
            "select status, records, chain from dns where name = ? and rtype = ?", (name, rtype)
        ).fetchone()
        if row is None:
            return None
        status, records, chain = row
        return Answer(
            name, rtype, Status(status), tuple(json.loads(records)), tuple(json.loads(chain))
        )

    def keep_answer(self, answer: Answer) -> None:
        if answer.answered:
            self.db.execute(
                "insert or replace into dns values (?, ?, ?, ?, ?, ?)",
                (
                    answer.name,
                    answer.rtype,
                    answer.status.value,
                    json.dumps(answer.records),
                    json.dumps(answer.chain),
                    date.today().isoformat(),
                ),
            )
            self._wrote()

    def page(self, url: str) -> tuple[int, list[tuple[str, str]], bytes] | None:
        row = self.db.execute("select status, headers, body from http where url = ?", (url,))
        found = row.fetchone()
        if found is None:
            return None
        status, headers, body = found
        return status, [(k, v) for k, v in json.loads(headers)], body

    def keep_page(self, url: str, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.db.execute(
            "insert or replace into http values (?, ?, ?, ?, ?)",
            (url, status, json.dumps(headers), body, date.today().isoformat()),
        )
        self._wrote()

    def _wrote(self) -> None:
        self.writes += 1
        if self.writes % 1000 == 0:
            self.db.commit()

    def day(self, record: str, rtype: str) -> str:
        """The day a record was read: a page's URL, or a DNS name and type."""
        if rtype == "page":
            row = self.db.execute("select day from http where url = ?", (record,)).fetchone()
        else:
            row = self.db.execute(
                "select day from dns where name = ? and rtype = ?", (norm(record), rtype)
            ).fetchone()
        return str(row[0]) if row else date.today().isoformat()

    def close(self) -> None:
        self.db.commit()
        self.db.close()


class CachedResolver:
    """Answers from the cache, else from `inner`; two askers of one name share one query."""

    def __init__(self, inner: Resolver, cache: Cache) -> None:
        self.inner, self.cache = inner, cache
        self.inflight: dict[tuple[str, str], asyncio.Task[Answer]] = {}
        self.asked = self.failed = 0

    async def query(self, name: str, rtype: str) -> Answer:
        key = (norm(name), rtype.upper())
        if (kept := self.cache.answer(*key)) is not None:
            return kept
        if key not in self.inflight:
            self.inflight[key] = asyncio.ensure_future(self._ask(*key))
        try:
            return await self.inflight[key]
        finally:
            self.inflight.pop(key, None)

    async def _ask(self, name: str, rtype: str) -> Answer:
        self.asked += 1
        answer = await self.inner.query(name, rtype)
        self.failed += not answer.answered
        self.cache.keep_answer(answer)
        return answer


class CachedTransport(httpx.AsyncBaseTransport):
    """Pages from the cache, else from `inner`, kept decoded. One entry per URL, so each hop of
    a redirect is kept on its own."""

    def __init__(self, cache: Cache, inner: httpx.AsyncBaseTransport | None = None) -> None:
        self.cache = cache
        self.inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method != "GET":
            return await self.inner.handle_async_request(request)
        if (kept := self.cache.page(url)) is None:
            response = await self.inner.handle_async_request(request)
            try:
                body = (await response.aread())[:MAX_BODY]
            finally:
                await response.aclose()
            dropped = ("content-encoding", "content-length", "transfer-encoding")
            # Raw bytes as latin-1, so a header no codec agrees on comes back as it went in.
            raw = ((k.decode("latin-1"), v.decode("latin-1")) for k, v in response.headers.raw)
            headers = [(k, v) for k, v in raw if k.lower() not in dropped]
            self.cache.keep_page(url, response.status_code, headers, body)
            kept = (response.status_code, headers, body)
        status, headers, body = kept
        encoded = [(_raw(k), _raw(v)) for k, v in headers]
        return httpx.Response(status, headers=encoded, content=body, request=request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def _raw(text: str) -> bytes:
    """A kept header as bytes: latin-1, as it arrived, or UTF-8 for text latin-1 cannot hold."""
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError:
        return text.encode("utf-8")


# ---------------------------------------------------------------- what is wanted


def wanted(pending: dict[str, Any]) -> tuple[Wanted, ...]:
    """Every pending pattern, and every name of every pending selectors entry, in file order."""
    found: list[Wanted] = []
    for vendor, block in pending["vendors"].items():
        for kind in PATTERN_FIELDS:
            found += (Wanted(vendor, kind, entry["value"]) for entry in block.get(kind, ()))
        for entry in block.get("selectors", ()):
            found += (Wanted(vendor, "selectors", n.lower()) for n in _names(entry["shape"]))
    return tuple(found)


def _names(shape: dict[str, Any]) -> list[str]:
    if shape["kind"] == "fixed":
        return [str(n) for n in shape["names"]]
    return [f"{shape['prefix']}{n}" for n in range(1, int(shape["stop"]) + 1)]


# ---------------------------------------------------------------- one domain


class Hunter:
    """What every domain's hunt shares: the checker, the cache, the catalog and what is wanted."""

    def __init__(
        self, checker: Checker, cache: Cache, loaded: Catalog, todo: Iterable[Wanted]
    ) -> None:
        self.checker, self.cache, self.catalog = checker, cache, loaded
        self.by_field: defaultdict[str, list[Wanted]] = defaultdict(list)
        for w in todo:
            self.by_field[w.field].append(w)
        self.pending_names = tuple(dict.fromkeys(w.value for w in self.by_field["selectors"]))
        self.sweep = tuple(dict.fromkeys((*loaded.probe_selectors, *self.pending_names)))
        self.known: frozenset[str] = frozenset()  # every hunted domain, for naming zones

    async def hunt(self, rank: int, domain: str) -> Hunt:
        return await _Domain(self, rank, domain).run()


class _Domain:
    """One domain's hunt. Every query awaits the one before it."""

    def __init__(self, hunter: Hunter, rank: int, domain: str) -> None:
        self.h, self.domain = hunter, domain
        self.result = Hunt(rank, domain)
        self.found: dict[Wanted, Found] = {}
        self.shows: set[str] = set()  # vendors shown by anything but a selector's name
        self.shown_at: dict[str, set[str]] = {}  # vendors each name's own SPF and MX show

    async def run(self) -> Hunt:
        subdomains = await self.sending()
        for where in (self.domain, *subdomains):
            self.shown_at[where] = await self.spf(where) | await self.mx(where)
        await self.tokens()
        await self.reports()
        await self.labels()
        await self.dkim(self.domain, self.h.sweep)
        for where in subdomains:
            await self.dkim(where, self.ranked(where)[:SUBDOMAIN_PROBES])
        await self.networks(subdomains)
        await self.homepage()
        self.result.found = [
            f if f.wanted.field != "selectors" else _backed(f, f.wanted.vendor in self.shows)
            for f in self.found.values()
        ]
        return self.result

    async def ask(self, name: str, rtype: str) -> Answer:
        answer = await self.h.checker.query(name, rtype)
        if answer.ok and _under(name, self.domain):
            self.result.answered = True
        return answer

    async def confirm(self, w: Wanted, record: str, rtype: str) -> None:
        """Check `record` for `w` with verify_proofs' check, and keep it when found."""
        if w in self.found:
            return
        seen: Seen = await CHECKS[w.field](self.h.checker, record, w.value)
        if not seen.shows:
            return
        if w.field != "selectors":
            self.shows.add(w.vendor)
        proof = Proof(self.proof_domain(w.field, record), record, self.h.cache.day(record, rtype))
        self.found[w] = Found(w, self.result.rank, self.domain, proof, seen.observed)

    def proof_domain(self, kind: str, record: str) -> str:
        """The domain a proof names: where the key or report record sits, the hunted domain
        for a record under it, and otherwise the zone the record belongs to."""
        name = norm(record)
        if kind in ("selectors", "dkim_cname"):
            return name.split("._domainkey.", 1)[1]
        if kind == "reporting" or name.startswith("https://"):
            return self.domain
        return self.domain if _under(name, self.domain) else zone(name, self.h.known)

    # ------------------------------------------------------------ the sources

    async def sending(self) -> list[str]:
        """The engine's sending subdomains: labels that publish SPF or MX, or are delegated by NS
        to a service's nameservers, proven or pending."""
        found = []
        for label in self.h.catalog.sending_labels:
            name = f"{label}.{self.domain}"
            txt = await self.ask(name, "TXT")
            mx = await self.ask(name, "MX")
            if spf_records(txt) or mx.ok or await self.delegation(name):
                found.append(name)
        return sorted(found)[:MAX_SUBDOMAINS]

    async def delegation(self, name: str) -> bool:
        """Whether `name` is delegated to a service's nameservers; confirms each pending one."""
        ns = await self.ask(name, "NS")
        hosts = () if ns.chain else ns.records
        delegated = any(self.note(self.h.catalog.delegation(h)) for h in hosts)
        for w in self.h.by_field["delegation_ns"]:
            if any(_under(h, w.value) for h in hosts):
                delegated = True
                self.shows.add(w.vendor)
                await self.confirm(w, name, "NS")
        return delegated

    async def spf(self, where: str) -> set[str]:
        """Walk every include and redirect below `where`; the vendors the walk met."""
        met: set[str] = set()
        todo, seen = [(norm(where), 0)], {norm(where)}
        while todo:
            name, depth = todo.pop(0)
            records = spf_records(await self.ask(name, "TXT"))
            if len(records) != 1:
                continue
            for term in terms(records[0]):
                if term.mechanism not in ("include", "redirect") or not term.value:
                    continue
                if "%{" in term.value:
                    continue
                target = norm(term.value)
                if vendor := self.note(self.h.catalog.spf(target)):
                    met.add(vendor)
                for w in self.h.by_field["spf_includes"]:
                    if _under(target, w.value):
                        met.add(w.vendor)
                        await self.confirm(w, name, "TXT")
                if depth < MAX_DEPTH and target not in seen:
                    seen.add(target)
                    todo.append((target, depth + 1))
        return met

    async def mx(self, where: str) -> set[str]:
        met: set[str] = set()
        for record in (await self.ask(where, "MX")).records:
            host = record.partition(" ")[2]
            if vendor := self.note(self.h.catalog.mx(host)):
                met.add(vendor)
            for w in self.h.by_field["mx"]:
                if _under(host, w.value):
                    met.add(w.vendor)
                    await self.confirm(w, where, "MX")
        return met

    async def tokens(self) -> None:
        if (await self.ask(self.domain, "TXT")).ok:
            for w in self.h.by_field["verification_txt"]:
                await self.confirm(w, self.domain, "TXT")

    async def reports(self) -> None:
        for name in (f"_dmarc.{self.domain}", f"_smtp._tls.{self.domain}"):
            answer = await self.ask(name, "TXT")
            for w in self.h.by_field["reporting"]:
                if answer.ok and w.value.lower() in " ".join(answer.records).lower():
                    await self.confirm(w, name, "TXT")

    async def labels(self) -> None:
        loaded = self.h.catalog
        wildcard = (await self.ask(f"{CANARY}.{self.domain}", "CNAME")).target
        for label in loaded.cname_labels:
            name = f"{label}.{self.domain}"
            answer = await self.ask(name, "CNAME")
            if not answer.chain or answer.chain[0] == wildcard:
                continue
            if label in loaded.other_cnames:
                continue
            if credited := loaded.label_cname(label, answer.chain[0]):
                self.note(credited[0])
            kind = "tracking" if label in loaded.tracking_labels else "return_path"
            for w in self.h.by_field[kind]:
                if any(_under(hop, w.value) for hop in answer.chain):
                    await self.confirm(w, name, "CNAME")

    async def dkim(self, where: str, names: Iterable[str]) -> None:
        canary = await self.ask(f"{CANARY}._domainkey.{where}", "TXT")
        if canary.chain or any("p=" in r for r in canary.records):
            return  # a wildcard: every name would answer
        pending = frozenset(self.h.pending_names)
        for selector in names:
            record = f"{selector}._domainkey.{where}"
            answer = await self.ask(record, "TXT")
            if not answer.ok and not answer.chain:
                continue
            hosts: set[str] = set()
            if vendor := self.note(self.h.catalog.dkim_cname(answer.chain)):
                hosts.add(vendor)
            for w in self.h.by_field["dkim_cname"]:
                if any(_under(hop, w.value) for hop in answer.chain):
                    hosts.add(w.vendor)
                    await self.confirm(w, record, "CNAME")
            if selector in pending and any("p=" in r for r in answer.records):
                for w in self.h.by_field["selectors"]:
                    # A key another vendor hosts is that vendor's: SendGrid lets a customer
                    # name its selector mc1, which proves nothing about Mimecast.
                    if w.value == selector and not hosts - {w.vendor}:
                        await self.confirm(w, record, "TXT")

    def ranked(self, where: str) -> list[str]:
        """The pending names for a sending subdomain: those of vendors its own SPF or MX shows
        first, then the rest in file order."""
        shown = self.shown_at.get(where, set())
        first = [w.value for w in self.h.by_field["selectors"] if w.vendor in shown]
        return list(dict.fromkeys((*first, *self.h.pending_names)))

    async def networks(self, subdomains: list[str]) -> None:
        """Every origin network of each address, read by the map's own networks.owner; a wanted
        one is confirmed by verify_proofs' check, which credits it as the map does."""
        wanted_asns = {w.value.upper(): w for w in self.h.by_field["networks"]}
        names = (self.domain, f"www.{self.domain}", f"mail.{self.domain}", *subdomains)
        for name in dict.fromkeys(names):
            answer = await self.ask(name, "A")
            for ip in answer.records:
                try:
                    address = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                owner = await networks.owner(self.h.checker.ctx, address)
                for asn in owner.asns if owner else ():
                    if w := wanted_asns.get(asn):
                        await self.confirm(w, name, "A")

    async def homepage(self) -> None:
        url = f"https://{self.domain}/"
        page = await _page(self.h.checker, url)
        if isinstance(page, Seen):
            return
        self.result.answered = True
        text = page.text.lower()
        for kind in ("website", "subprocessor_names"):
            for w in self.h.by_field[kind]:
                if w.value.lower() in text:
                    await self.confirm(w, url, "page")

    def note(self, vendor: str | None) -> str | None:
        """Count `vendor` as shown on the domain; returns it."""
        if vendor:
            self.shows.add(vendor)
        return vendor


def _backed(found: Found, backed: bool) -> Found:
    return Found(found.wanted, found.rank, found.hunted, found.proof, found.observed, backed)


def zone(name: str, known: frozenset[str]) -> str:
    """The zone a name outside the hunted domain belongs to: the shortest hunted domain it is
    under, else its last two labels, or three under a registry's second level (co.uk)."""
    labels = norm(name).split(".")
    for start in range(len(labels) - 2, -1, -1):
        if (candidate := ".".join(labels[start:])) in known:
            return candidate
    keep = 3 if len(labels) > 2 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2 else 2
    return ".".join(labels[-keep:])


# ---------------------------------------------------------------- every domain


def read_domains(path: Path) -> tuple[str, list[str]]:
    """The file's comment lines, joined, and its domains in rank order without repeats."""
    about: list[str] = []
    domains: list[str] = []
    for line in path.read_text().splitlines():
        text = line.strip()
        if text.startswith("#"):
            about.append(text.lstrip("#").strip())
        elif text:
            domains.append(norm(text))
    return " ".join(about), list(dict.fromkeys(domains))


async def hunt_all(hunter: Hunter, domains: list[str], parallel: int) -> list[Hunt]:
    """Every domain's hunt, `parallel` at a time, in rank order."""
    hunter.known = frozenset(domains)
    limit = asyncio.Semaphore(parallel)
    done = 0

    async def one(rank: int, domain: str) -> Hunt:
        nonlocal done
        async with limit:
            result = await hunter.hunt(rank, domain)
        done += 1
        if done % 100 == 0 or done == len(domains):
            print(f"{done:,} of {len(domains):,} domains", file=sys.stderr, flush=True)
        return result

    return list(await asyncio.gather(*(one(r, d) for r, d in enumerate(domains, 1))))


def best(hunts: Iterable[Hunt]) -> tuple[dict[Wanted, Found], dict[Wanted, int]]:
    """For each pattern found, the find on the highest ranked domain that showed it, and how
    many domains showed it."""
    proven: dict[Wanted, Found] = {}
    count: defaultdict[Wanted, int] = defaultdict(int)
    for hunt in sorted(hunts, key=lambda h: h.rank):
        for found in hunt.found:
            count[found.wanted] += 1
            proven.setdefault(found.wanted, found)
    return proven, dict(count)


def report(
    about: str,
    todo: tuple[Wanted, ...],
    hunts: list[Hunt],
    proven: dict[Wanted, Found],
    count: dict[Wanted, int],
) -> str:
    silent = [h.domain for h in sorted(hunts, key=lambda h: h.rank) if not h.answered]
    lines = [f"Hunted {len(hunts):,} domains. {about}".rstrip(), ""]
    lines.append(f"Proven: {len(proven)} of {len(todo)} pending patterns")
    for w in todo:
        if f := proven.get(w):
            via = f" (through {f.hunted})" if f.proof.domain != f.hunted else ""
            lines.append(
                f"  {w.vendor} {w.field} {w.value}: {f.proof.domain}{via}, rank {f.rank}, "
                f"{f.proof.record} ({f.proof.date}); shown by {_domains(count[w])}"
            )
            lines.append(f"      {_short(f.observed)}")
            if not f.backed:
                lines.append(f"      nothing else on {f.hunted} shows {w.vendor}")
    pending = [w for w in todo if w not in proven]
    lines += ["", f"Still pending: {len(pending)} of {len(todo)}"]
    lines += [f"  {w.vendor} {w.field} {w.value}" for w in pending]
    lines += ["", f"Domains that answered nothing at all: {len(silent)}"]
    lines += [f"  {domain}" for domain in silent]
    lines += [
        "",
        f"{len(proven)} proven, {len(pending)} still pending, "
        f"{_domains(len(silent))} answered nothing",
    ]
    return "\n".join(lines)


def _domains(n: int) -> str:
    return "1 domain" if n == 1 else f"{n:,} domains"


def _short(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ---------------------------------------------------------------- the move


def move(
    vendors: dict[str, Any], pending: dict[str, Any], proven: dict[Wanted, Found], hunted: str
) -> int:
    """Move every proven pattern from `pending` into `vendors` with its proof, in place. A
    selectors entry moves once every name in it is proven; a block whose patterns all move
    leaves pending, and every other block's checked note gains `hunted`. Returns the number of
    entries moved."""
    moved = 0
    for vendor in list(pending["vendors"]):
        block = pending["vendors"][vendor]
        taken: dict[str, list[dict[str, Any]]] = {}
        for kind in (*PATTERN_FIELDS, "selectors"):
            keep: list[dict[str, Any]] = []
            for entry in block.get(kind, ()):
                if (done := _proven_entry(vendor, kind, entry, proven)) is None:
                    keep.append(entry)
                else:
                    taken.setdefault(kind, []).append(done)
            if kind in block:
                if keep:
                    block[kind] = keep
                else:
                    del block[kind]
        if any(kind in block for kind in (*PATTERN_FIELDS, "selectors")):
            block["checked"] = f"{block['checked']} {hunted}"
        else:
            del pending["vendors"][vendor]
        if not taken:
            continue
        moved += sum(map(len, taken.values()))
        target = vendors["vendors"].setdefault(vendor, {"category": block["category"]})
        for kind, entries in taken.items():
            target.setdefault(kind, []).extend(entries)
    vendors["vendors"] = dict(sorted(vendors["vendors"].items(), key=lambda i: i[0].casefold()))
    return moved


def _proven_entry(
    vendor: str, kind: str, entry: dict[str, Any], proven: dict[Wanted, Found]
) -> dict[str, Any] | None:
    """The entry as vendors.json takes it, with its proof, or None while any name is unproven."""
    if kind != "selectors":
        found = proven.get(Wanted(vendor, kind, entry["value"]))
        return None if found is None else {**entry, "proof": asdict(found.proof)}
    finds = [proven.get(Wanted(vendor, kind, n.lower())) for n in _names(entry["shape"])]
    if not finds or None in finds:
        return None
    proofs = [asdict(f.proof) for f in finds if f]
    rest = {k: v for k, v in entry.items() if k != "shape"}
    return {
        "shape": entry["shape"],
        "source": "pattern",
        "reference": None,
        "proof": proofs[0] if entry["shape"]["kind"] != "fixed" or len(proofs) == 1 else proofs,
        **rest,
    }


def write(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


# ---------------------------------------------------------------- the command


async def main(
    argv: list[str] | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> int:
    parser = argparse.ArgumentParser(description="Hunt proofs of pending patterns on domains.")
    parser.add_argument("domains", nargs="?", type=Path, default=DOMAINS)
    parser.add_argument("--cache", type=Path, default=CACHE, help="where answers are kept")
    parser.add_argument("--parallel", type=int, default=PARALLEL, help="domains at a time")
    parser.add_argument("--nameserver", action="append", help="resolver to ask (repeatable)")
    parser.add_argument("--doh", action="store_true", help="look up DNS over HTTPS (Cloudflare)")
    parser.add_argument("--move", action="store_true", help="move proven patterns to vendors.json")
    args = parser.parse_args(argv)

    about, domains = read_domains(args.domains)
    pending = json.loads(PENDING.read_text())
    todo = wanted(pending)
    cache = Cache(args.cache)
    dns_http = doh_client()
    inner: Resolver = (
        DohResolver(dns_http)
        if args.doh
        else SystemResolver(timeout=TIMEOUT, nameservers=args.nameserver)
    )
    resolver = CachedResolver(inner, cache)
    try:
        async with dns_http, httpx.AsyncClient(transport=CachedTransport(cache, transport)) as http:
            loaded = catalog.load()
            # Whose each network is, proven or pending, for the map's rule in the network check.
            owners = loaded.networks | {w.value: w.vendor for w in todo if w.field == "networks"}
            hunter = Hunter(Checker(resolver, http, owners), cache, loaded, todo)
            hunts = await hunt_all(hunter, domains, args.parallel)
    finally:
        cache.close()
    proven, count = best(hunts)
    print(report(about, todo, hunts, proven, count))
    print(f"{resolver.asked:,} DNS queries asked, {resolver.failed:,} failed", file=sys.stderr)
    if args.move:
        vendors = json.loads(VENDORS.read_text())
        day = max((f.proof.date for f in proven.values()), default=date.today().isoformat())
        hunted = (
            f"{day}, the {len(domains):,} domains in data/hunt_domains.txt (tools/hunt_proofs.py):"
            " none of the entries left here was found there either."
        )
        moved = move(vendors, pending, proven, hunted)
        catalog.build(vendors)  # refuses any proof that could not show its pattern
        write(VENDORS, vendors)
        write(PENDING, pending)
        print(f"Moved {moved} entries to vendors.json", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
