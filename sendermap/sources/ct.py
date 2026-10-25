"""Certificate transparency: every name a certificate was issued for under the domain, read once
per map from the certificate logs, and, with --ct, resolved now and matched to services the same
way the DNS sources match.

The logs are read through a list of providers: Cert Spotter always, crt.sh only with --ct, since
it also holds expired certificates, which the possible past vendor check needs. Each answer is
cached for a day. Every provider's rows go through one parse into one set of names; the subdomain
search takes its candidates from that set, and the resolve and match pass below reads it too.

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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from ..dns import Answer, Status, norm
from ..model import (
    CertificateEvidence,
    Checked,
    Claim,
    CtProvider,
    CtStatus,
    CtSummary,
    Evidence,
    Gap,
    GapKind,
    Historical,
    Kind,
    Observed,
)
from . import Context, http_failure, labels, mx, networks

CACHE_FOR = timedelta(hours=24)
MAX_NAMES = 200
BACKOFF = 2.0  # seconds before a provider's first retry, doubled before the next

# One logged name on one certificate, as a provider gives it: (name, not_before, not_after).
Row = tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class Provider:
    """One certificate log reader: where it is asked, and how its answer becomes rows."""

    name: str  # in gaps and the summary
    key: str  # its directory in the cache
    url: str
    params: Callable[[str], dict[str, str]]
    rows: Callable[[list[Any]], list[Row]]
    tries: int  # the first request and the retries
    timeout: float

    def page(self, domain: str) -> str:
        return str(httpx.URL(self.url, params=self.params(domain)))


def _cert_spotter_rows(issuances: list[Any]) -> list[Row]:
    return [
        (str(raw), _date(issuance.get("not_before")), _date(issuance.get("not_after")))
        for issuance in issuances
        if isinstance(issuance, dict)
        for raw in issuance.get("dns_names") or ()
    ]


def _crt_sh_rows(entries: list[Any]) -> list[Row]:
    return [
        (raw, _date(entry.get("not_before")), _date(entry.get("not_after")))
        for entry in entries
        if isinstance(entry, dict)
        for raw in str(entry.get("name_value", "")).split("\n")
    ]


def _date(value: object) -> str:
    """A validity date as crt.sh writes it, so dates from both providers compare: Cert Spotter's
    trailing Z (both are UTC) is dropped."""
    return str(value or "").removesuffix("Z")


CERT_SPOTTER = Provider(
    "Cert Spotter",
    "certspotter",
    "https://api.certspotter.com/v1/issuances",
    lambda domain: {"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
    _cert_spotter_rows,
    tries=1,
    timeout=8.0,
)
# crt.sh often times out, so it is asked three times, waiting longer before each retry.
CRT_SH = Provider(
    "crt.sh",
    "crtsh",
    "https://crt.sh/",
    lambda domain: {"q": f"%.{domain}", "output": "json"},
    _crt_sh_rows,
    tries=3,
    timeout=30.0,
)


@dataclass(frozen=True, slots=True)
class Logged:
    """One name and the validity of the latest certificate naming it."""

    name: str
    not_before: str
    not_after: str


@dataclass(frozen=True, slots=True)
class Logs:
    """Every name the providers logged under the domain, read once per map: the names, what
    each provider did, and its gaps and the pages asked."""

    names: tuple[Logged, ...] = ()
    providers: tuple[CtProvider, ...] = ()
    observed: Observed = field(default_factory=Observed)

    @property
    def answered(self) -> bool:
        return any(p.status in (CtStatus.READ, CtStatus.CACHED) for p in self.providers)


def default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sendermap" / "ct"


def logged_names(rows: Iterable[Row], domain: str) -> list[Logged]:
    """Names under `domain` from every provider's rows, sorted: lowercased, a leading `*.`
    dropped (the name below a wildcard is a name too), and repeats, other wildcards and names
    outside the domain dropped. A name on several certificates keeps the dates of the one that
    expires last."""
    latest: dict[str, Logged] = {}
    for raw, not_before, not_after in rows:
        name = norm(raw).removeprefix("*.")
        if not name.endswith("." + domain) or "*" in name:
            continue
        found = Logged(name, not_before, not_after)
        if name not in latest or found.not_after > latest[name].not_after:
            latest[name] = found
    return [latest[name] for name in sorted(latest)]


async def read_logs(ctx: Context, cache: Path | None, *, expired: bool) -> Logs:
    """Ask each provider once: Cert Spotter always, crt.sh only when `expired` (--ct). A provider
    that failed or was off is a gap worded with its name and what happened."""
    asked = await asyncio.gather(
        _ask(ctx, cache, CERT_SPOTTER), _ask(ctx, cache, CRT_SH) if expired else _off(ctx, CRT_SH)
    )
    rows = [row for found, _, _ in asked for row in found]
    return Logs(
        tuple(logged_names(rows, ctx.domain)),
        tuple(provider for _, provider, _ in asked),
        sum((observed for _, _, observed in asked), Observed()),
    )


async def _ask(
    ctx: Context, cache: Path | None, provider: Provider
) -> tuple[list[Row], CtProvider, Observed]:
    page = provider.page(ctx.domain)
    asked = Observed(checked=(Checked(ctx.domain, pages=(page,)),))
    rows = _cached(cache, provider, ctx.domain, ctx.checked_at)
    status = CtStatus.CACHED
    if rows is None:
        fetched = await _fetch(ctx.http, provider, ctx.domain)
        if isinstance(fetched, str):
            question = f"certificate transparency, {provider.name}: GET {page}"
            gap = Gap(question, fetched, GapKind.CERTIFICATE_LOG)
            unavailable = CtProvider(provider.name, CtStatus.UNAVAILABLE)
            return [], unavailable, asked + Observed(gaps=(gap,))
        rows, status = fetched, CtStatus.READ
        _store(cache, provider, ctx.domain, ctx.checked_at, rows)
    count = len(logged_names(rows, ctx.domain))
    return rows, CtProvider(provider.name, status, count), asked


async def _off(ctx: Context, provider: Provider) -> tuple[list[Row], CtProvider, Observed]:
    asked = f"certificate transparency, {provider.name}: GET {provider.page(ctx.domain)}"
    gap = Gap(
        asked, "not asked: read only with --ct (it also holds expired certificates)", GapKind.OFF
    )
    return [], CtProvider(provider.name), Observed(gaps=(gap,))


async def collect(ctx: Context, logs: Logs) -> tuple[Observed, CtSummary]:
    """The resolve and match pass (--ct): each logged name, up to MAX_NAMES, resolved now."""
    if not logs.answered:
        return Observed(), CtSummary(CtStatus.UNAVAILABLE, providers=logs.providers)
    names = logs.names
    picked = names[:MAX_NAMES]
    observed = Observed()
    if dropped := len(names) - len(picked):
        happened = (
            f"{dropped} of {len(names)} not resolved. The first {MAX_NAMES} in alphabetical "
            f"order were resolved (cap {MAX_NAMES})."
        )
        gap = Gap(
            "names from certificate logs", happened, GapKind.CERTIFICATE_LOG, dropped, MAX_NAMES
        )
        observed += Observed(gaps=(gap,))
    published, range_gaps = await networks.published_ranges(ctx)
    read = await asyncio.gather(*(_read(ctx, logged, published) for logged in picked))
    observed = sum((o for o, _ in read), observed) + Observed(gaps=range_gaps)
    gone = sum(1 for _, unnamed in read if unnamed)
    return observed, CtSummary(CtStatus.READ, len(names), len(picked), gone, logs.providers)


async def _read(
    ctx: Context, logged: Logged, published: networks.Published
) -> tuple[Observed, bool]:
    """What one logged name shows now, and whether it is gone without naming any service."""
    name = logged.name
    cname, address, mail = await asyncio.gather(
        ctx.dns.query(name, "CNAME"), ctx.dns.query(name, "A"), ctx.dns.query(name, "MX")
    )
    if not all(a.answered for a in (cname, address, mail)):
        asked = f"name from certificate logs: CNAME, A and MX at {name}"
        gap = Gap(asked, "lookup failed", GapKind.CERTIFICATE_LOG, 1)
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
            service, support = networks.credited(ctx, announced), announced.evidence
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


async def _fetch(
    http: httpx.AsyncClient | None, provider: Provider, domain: str
) -> list[Row] | str:
    """The provider's rows for every name under `domain`, or what happened on the last try."""
    if http is None:
        return "not fetched: no web client"
    failure = ""
    for attempt in range(provider.tries):
        if attempt:
            await asyncio.sleep(BACKOFF * 2 ** (attempt - 1))
        try:
            response = await http.get(
                provider.url, params=provider.params(domain), timeout=provider.timeout
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
            return provider.rows(data)
        failure = "the answer was not a list of certificates"
    tries = "1 try" if provider.tries == 1 else f"{provider.tries} tries"
    return f"unavailable after {tries}: {failure}"


def _cached(cache: Path | None, provider: Provider, domain: str, now: datetime) -> list[Row] | None:
    """The rows stored for `domain` less than CACHE_FOR before `now`, if any."""
    if cache is None:
        return None
    try:
        stored = json.loads((cache / provider.key / f"{domain}.json").read_text())
        fetched = datetime.fromisoformat(stored["fetched_at"])
        rows = [(str(n), str(b), str(a)) for n, b, a in stored["rows"]]
        fresh = timedelta(0) <= now - fetched < CACHE_FOR  # TypeError when one has no zone
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return rows if fresh else None


def _store(
    cache: Path | None, provider: Provider, domain: str, now: datetime, rows: list[Row]
) -> None:
    """Keep the rows; a cache that cannot be written is skipped."""
    if cache is None:
        return
    try:
        (cache / provider.key).mkdir(parents=True, exist_ok=True)
        body = json.dumps({"fetched_at": now.isoformat(), "rows": rows})
        (cache / provider.key / f"{domain}.json").write_text(body)
    except OSError:
        return
