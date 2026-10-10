"""Certificate transparency: every name a certificate was issued for under the domain, from
crt.sh, resolved now and matched to services the same way the DNS sources match.

A certificate shows a name existed; only what the name resolves to today shows a service. A
claim from a logged name carries CertificateEvidence, which is how it is told apart, and has
the Kind the DNS path gives the same record: a subdomain MX, or a bounce, tracking or
autodiscover CNAME when the name's label is one the DNS path asks for. A CNAME at any other
label says only that it points into the service's zone, since the label does not say what for.
A name that resolves no more but whose leftover CNAME points at a service is reported as a
possible past vendor, never as a current sender.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from ..dns import Answer, Status, norm
from ..model import (
    CertificateEvidence,
    Checked,
    Claim,
    CtStatus,
    CtSummary,
    Evidence,
    Gap,
    Historical,
    Kind,
    Observed,
)
from . import Context, http_failure, labels, mx, networks

CRT_SH = "https://crt.sh/"
TRIES = 3  # the first request and two retries
BACKOFF = 2.0  # seconds before the first retry, doubled before the next
TIMEOUT = 30.0
CACHE_FOR = timedelta(hours=24)
MAX_NAMES = 200


@dataclass(frozen=True, slots=True)
class Logged:
    """One name and the validity of the latest certificate naming it."""

    name: str
    not_before: str
    not_after: str


def default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sendermap" / "crtsh"


def logged_names(entries: list[dict[str, Any]], domain: str) -> list[Logged]:
    """Names under `domain` from crt.sh entries, sorted: each name_value split on newlines and
    lowercased, wildcards, repeats and names outside the domain dropped. A name on several
    certificates keeps the dates of the one that expires last."""
    latest: dict[str, Logged] = {}
    for entry in entries:
        for raw in str(entry.get("name_value", "")).split("\n"):
            name = norm(raw)
            if not name or "*" in name or not name.endswith("." + domain):
                continue
            found = Logged(name, str(entry.get("not_before", "")), str(entry.get("not_after", "")))
            if name not in latest or found.not_after > latest[name].not_after:
                latest[name] = found
    return [latest[name] for name in sorted(latest)]


async def collect(ctx: Context, cache: Path | None) -> tuple[Observed, CtSummary]:
    url = f"{CRT_SH}?q=%25.{ctx.domain}&output=json"
    asked = Checked(ctx.domain, pages=(url,))
    entries = _cached(cache, ctx.domain, ctx.checked_at)
    status = CtStatus.CACHED
    if entries is None:
        fetched = await _fetch(ctx.http, ctx.domain)
        if isinstance(fetched, str):
            gap = Gap(f"certificate transparency: GET {url}", fetched)
            return Observed(gaps=(gap,), checked=(asked,)), CtSummary(CtStatus.UNAVAILABLE)
        entries, status = fetched, CtStatus.READ
        _store(cache, ctx.domain, ctx.checked_at, entries)
    names = logged_names(entries, ctx.domain)
    picked = names[:MAX_NAMES]
    observed = Observed(checked=(asked,))
    if dropped := len(names) - len(picked):
        happened = (
            f"{dropped} of {len(names)} not resolved: only the first {MAX_NAMES} in "
            "alphabetical order were (cap)"
        )
        observed += Observed(gaps=(Gap("names from certificate logs", happened),))
    published, range_gaps = await networks.published_ranges(ctx)
    read = await asyncio.gather(*(_read(ctx, logged, published) for logged in picked))
    observed = sum((o for o, _ in read), observed) + Observed(gaps=range_gaps)
    gone = sum(1 for _, unnamed in read if unnamed)
    return observed, CtSummary(status, len(names), len(picked), gone)


async def _read(
    ctx: Context, logged: Logged, published: networks.Published
) -> tuple[Observed, bool]:
    """What one logged name shows now, and whether it is gone without naming any service."""
    name = logged.name
    cname, address, mail = await asyncio.gather(
        ctx.dns.query(name, "CNAME"), ctx.dns.query(name, "A"), ctx.dns.query(name, "MX")
    )
    if not all(a.answered for a in (cname, address, mail)):
        gap = Gap(f"name from certificate logs: CNAME, A and MX at {name}", "lookup failed")
        return Observed(gaps=(gap,)), False
    label = name.split(".", 1)[0]
    chain = cname.chain or address.chain
    match = next(
        ((hop, found) for hop in chain if (found := ctx.catalog.label_cname(label, hop))), None
    )
    gone = address.status is Status.NXDOMAIN and mail.status is not Status.OK
    if gone:
        if match is None:
            return Observed(), True
        hop, (service, _) = match
        evidence = _evidence(ctx, logged, "CNAME", " -> ".join(chain), hop)
        return Observed(historical=(Historical(service, evidence),)), False
    if match:
        hop, (service, label_kind) = match
        evidence = _evidence(ctx, logged, "CNAME", " -> ".join(chain), hop)
        relative = name.removesuffix("." + ctx.domain)
        known = relative in ctx.catalog.cname_labels or label in ctx.catalog.tracking_labels
        kind = labels.KINDS[label_kind] if known else Kind.CT_CNAME
        return Observed((Claim(service, kind, name, evidence),)), False
    for record in mail.records:
        if receiver := ctx.catalog.mx(mx.exchange(record)):
            evidence = _evidence(ctx, logged, "MX", record)
            kind = mx.kind_at(ctx, receiver, name)
            return Observed((Claim(receiver, kind, name, evidence),)), False
    return await _by_address(ctx, logged, address, published), False


async def _by_address(
    ctx: Context,
    logged: Logged,
    address: Answer,
    published: networks.Published,
) -> Observed:
    """The first address in a range one service publishes, or in a network a service owns, with
    the published range or the network's answer as support. A shared cloud is never credited."""
    for ip in address.records:
        try:
            network = ipaddress.ip_network(ip)
        except ValueError:
            continue
        candidates = networks.published_by(network, published)
        service: str | None = None
        support: tuple[Evidence, ...] = ()
        if len(candidates) == 1:
            ((service, source),) = candidates.items()
            support = (source,)
        elif announced := await networks.owner(ctx, network[0]):
            service, support = ctx.catalog.network(announced.asn), announced.evidence
        if service:
            evidence = _evidence(ctx, logged, "A", ip)
            claim = Claim(service, Kind.CT_ADDRESS, logged.name, evidence, support)
            return Observed((claim,))
    return Observed()


def _evidence(
    ctx: Context, logged: Logged, rtype: str, record: str, target: str | None = None
) -> CertificateEvidence:
    value = (
        f"{rtype} {record}; named in a certificate valid {logged.not_before[:10]} to "
        f"{logged.not_after[:10]}"
    )
    return CertificateEvidence(
        logged.name,
        "certificate",
        value,
        ctx.checked_at,
        logged.not_before,
        logged.not_after,
        target,
    )


async def _fetch(http: httpx.AsyncClient | None, domain: str) -> list[dict[str, Any]] | str:
    """crt.sh's entries for every name under `domain`, or what happened on the last try. It often
    times out, so it is asked up to TRIES times, waiting longer before each retry."""
    if http is None:
        return "not fetched: no web client"
    failure = ""
    for attempt in range(TRIES):
        if attempt:
            await asyncio.sleep(BACKOFF * 2 ** (attempt - 1))
        try:
            response = await http.get(
                CRT_SH, params={"q": f"%.{domain}", "output": "json"}, timeout=TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as e:
            failure = http_failure(e)
            continue
        except ValueError:
            failure = "the answer was not JSON"
            continue
        if isinstance(data, list):
            return data
        failure = "the answer was not a list of certificates"
    return f"unavailable after {TRIES} tries: {failure}"


def _cached(cache: Path | None, domain: str, now: datetime) -> list[dict[str, Any]] | None:
    """The entries stored for `domain` less than CACHE_FOR before `now`, if any."""
    if cache is None:
        return None
    try:
        stored = json.loads((cache / f"{domain}.json").read_text())
        fetched = datetime.fromisoformat(stored["fetched_at"])
        entries = stored["entries"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    fresh = timedelta(0) <= now - fetched < CACHE_FOR
    return entries if fresh and isinstance(entries, list) else None


def _store(cache: Path | None, domain: str, now: datetime, entries: list[dict[str, Any]]) -> None:
    """Keep the fields this source reads; a cache that cannot be written is skipped."""
    if cache is None:
        return
    kept = [
        {k: e.get(k) for k in ("name_value", "not_before", "not_after")}
        for e in entries
        if isinstance(e, dict)
    ]
    try:
        cache.mkdir(parents=True, exist_ok=True)
        body = json.dumps({"fetched_at": now.isoformat(), "entries": kept})
        (cache / f"{domain}.json").write_text(body)
    except OSError:
        return
