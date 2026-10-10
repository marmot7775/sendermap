"""Runs every source against a domain and assembles the map.

Two phases. The first reads what needs no prior knowledge: MX, SPF, tokens, report addresses,
labels, the website, sending subdomains. The second uses it: DKIM names a generic selector after
a service SPF or MX already shows; the networks source looks up the IP ranges the SPF walk found;
each sending subdomain gets its own smaller scan, ranked by its own MX and SPF.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import AsyncExitStack
from datetime import datetime
from pathlib import Path

import httpx

from . import catalog as catalog_module
from .dns import Lookups, Resolver, SystemResolver
from .infer import backed_selectors, services
from .model import (
    Claim,
    CtStatus,
    CtSummary,
    Evidence,
    Finding,
    Gap,
    Kind,
    Observed,
    Run,
    SenderMap,
    Severity,
)
from .selectors import Rule, load_rules, probe_order, rank_rules
from .sources import (
    Context,
    bimi,
    ct,
    dkim,
    labels,
    mta_sts,
    mx,
    networks,
    reports,
    spf,
    subdomains,
    tokens,
    web,
)

Progress = Callable[[str], Awaitable[None]]
MAX_SUBDOMAINS = 30
# DKIM names probed per sending subdomain, besides the ones its own SPF or MX backs.
SUBDOMAIN_PROBES = 27


async def map_domain(
    domain: str,
    *,
    checked_at: datetime,
    resolver: Resolver | None = None,
    http: httpx.AsyncClient | None = None,
    use_web: bool = True,
    use_subdomains: bool = True,
    use_ct: bool = False,
    ct_cache: Path | None = None,
    progress: Progress | None = None,
) -> SenderMap:
    """Map the services that send email as `domain`, with the evidence for each.

    `checked_at` is the moment the map is dated by, timezone-aware; the caller says when, so the
    same DNS answers and the same moment give the same map. `use_ct` adds every name crt.sh has
    logged a certificate for, cached for a day in `ct_cache` (None: no cache).
    """
    if checked_at.tzinfo is None:
        raise ValueError("checked_at needs a timezone")
    domain = clean_domain(domain)
    started = time.perf_counter()
    online = use_web or use_subdomains or use_ct
    async with AsyncExitStack() as stack:
        if http is None and online:
            http = await stack.enter_async_context(httpx.AsyncClient(http2=False))
        ctx = Context(
            domain,
            Lookups(resolver or SystemResolver()),
            catalog_module.load(),
            checked_at,
            http if online else None,
        )
        rules = load_rules()
        say = progress or _quiet

        await say("Reading MX, SPF, DMARC and the website")
        async with asyncio.TaskGroup() as tg:
            spf_task = tg.create_task(spf.collect(ctx, domain))
            evidence = [
                tg.create_task(_guard(source, what))
                for source, what in (
                    (mx.collect(ctx, domain), "MX"),
                    (tokens.collect(ctx), "verification tokens"),
                    (reports.collect(ctx), "report addresses"),
                    (labels.collect(ctx, domain), "bounce and tracking CNAMEs"),
                    (mta_sts.collect(ctx), "the MTA-STS policy"),
                    (web.collect(ctx) if use_web else _skipped(_NO_WEB), "the website"),
                )
            ]
            logo_task = tg.create_task(bimi.logo(ctx))
            subs_task = tg.create_task(_discover(ctx) if use_subdomains else _no_subdomains())
            ct_task = tg.create_task(_certificates(ctx, ct_cache) if use_ct else _ct_off())
        found, tree = spf_task.result()
        logged, ct_summary = ct_task.result()
        discovered = subs_task.result()
        apex = sum((task.result() for task in evidence), found) + Observed(gaps=discovered.gaps)
        logo = logo_task.result()

        await say("Scanning DKIM keys and the networks in SPF")
        backed = backed_selectors(apex.claims, ctx.catalog)
        selectors = await _probe_order(ctx, rules, domain, tree.includes, backed)
        deep = await asyncio.gather(
            dkim.collect(ctx, domain, selectors, backed),
            networks.collect(ctx, domain, tree.ranges),
        )

        picked = discovered.sending[:MAX_SUBDOMAINS]
        if dropped := len(discovered.sending) - len(picked):
            happened = (
                f"{dropped} of {len(discovered.sending)} not checked: only the first "
                f"{MAX_SUBDOMAINS} in alphabetical order were (cap)"
            )
            apex += Observed(gaps=(Gap("sending subdomains", happened),))
        await say(f"Checking {len(picked)} sending subdomains")
        under = await asyncio.gather(*(_subdomain(ctx, rules, name) for name in picked))

        observed = sum((*deep, *under), apex) + logged
        result = SenderMap(
            domain=domain,
            services=services(observed.claims, ctx.catalog, domain),
            run=Run(
                checked_at=checked_at,
                elapsed=round(time.perf_counter() - started, 2),
                lookups=ctx.dns.count,
            ),
            findings=_sorted(observed.findings + _cross_findings(ctx, observed)),
            unknowns=tuple(dict.fromkeys(observed.unknowns)),
            gaps=tuple(dict.fromkeys(observed.gaps)),
            subdomains_checked=tuple(picked),
            checked=observed.checked_by_name(),
            ct=ct_summary,
            historical=tuple(dict.fromkeys(observed.historical)),
            logo=logo,
        )
        await say("Done")
        return result


async def _subdomain(ctx: Context, rules: tuple[Rule, ...], name: str) -> Observed:
    (found, tree), received = await asyncio.gather(spf.collect(ctx, name), mx.collect(ctx, name))
    first = found + received
    backed = backed_selectors(first.claims, ctx.catalog)
    order = await _probe_order(ctx, rules, name, tree.includes, backed)
    probed = (*order[:SUBDOMAIN_PROBES], *backed)
    keys, owned = await asyncio.gather(
        dkim.collect(ctx, name, probed, backed),
        networks.collect(ctx, name, tree.ranges),
    )
    budget = Observed()
    if unasked := len(set(order) - set(probed)):
        happened = (
            f"{unasked} of {len(order)} not asked: only the first {SUBDOMAIN_PROBES} and the "
            "names its own SPF or MX backs were (cap)"
        )
        budget = Observed(gaps=(Gap(f"DKIM selectors at {name}", happened),))
    return first + keys + owned + budget


async def _probe_order(
    ctx: Context,
    rules: tuple[Rule, ...],
    where: str,
    spf_includes: Iterable[str],
    backed: Mapping[str, Claim],
) -> tuple[str, ...]:
    """The DKIM sweep for `where`, with the rules its own MX and SPF hint at moved first."""
    # The MX source already asked, so this query is a cache hit.
    mx_hosts = [h for r in (await ctx.dns.query(where, "MX")).records if (h := mx.exchange(r))]
    ranked = rank_rules(rules, mx_hosts, spf_includes)
    return probe_order(ranked, (*ctx.catalog.probe_selectors, *backed))


def _cross_findings(ctx: Context, observed: Observed) -> tuple[Finding, ...]:
    """A note for each security gateway in the domain's MX, carrying those MX records."""
    gateways: dict[str, list[Evidence]] = {}
    for c in observed.claims:
        if c.kind is Kind.MX and ctx.catalog.category(c.service) == "Security gateway":
            gateways.setdefault(c.service, []).append(c.evidence)
    return tuple(
        Finding(
            Severity.NOTE,
            f"MX at {ctx.domain} points at {g}, a security gateway",
            "Inferred from the MX records: a security gateway filters incoming mail and hands it "
            "on to the server that holds the mailboxes, and MX records do not say which server "
            "that is.",
            tuple(evidence),
        )
        for g, evidence in sorted(gateways.items())
    )


def _sorted(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    order = list(Severity)
    return tuple(sorted(dict.fromkeys(findings), key=lambda f: order.index(f.severity)))


_NO_WEB = Gap("the website", "not read: web checks were turned off (--no-web)")
_NO_SUBDOMAINS = Gap(
    "sending subdomains", "not searched: subdomain checks were turned off (--no-subdomains)"
)


async def _guard(source: Awaitable[Observed], what: str) -> Observed:
    """Run one source; if it breaks, record a gap instead of losing the whole map."""
    try:
        return await source
    except Exception as e:  # a source bug must not take down every other source
        return Observed(gaps=(Gap(what, f"the check crashed: {type(e).__name__}"),))


async def _discover(ctx: Context) -> subdomains.Found:
    """Sending subdomains; a crash here costs the subdomains, not the map, and says so."""
    try:
        return await subdomains.discover(ctx)
    except Exception as e:  # a source bug must not take down every other source
        crashed = Gap("sending subdomains", f"the search crashed: {type(e).__name__}")
        return subdomains.Found(gaps=(crashed,))


async def _certificates(ctx: Context, cache: Path | None) -> tuple[Observed, CtSummary]:
    """Certificate transparency; a crash here costs CT, not the map, and says so."""
    try:
        return await ct.collect(ctx, cache)
    except Exception as e:  # a source bug must not take down every other source
        crashed = Gap("certificate transparency", f"the check crashed: {type(e).__name__}")
        return Observed(gaps=(crashed,)), CtSummary(CtStatus.UNAVAILABLE)


async def _ct_off() -> tuple[Observed, CtSummary]:
    return Observed(), CtSummary()


async def _skipped(gap: Gap) -> Observed:
    return Observed(gaps=(gap,))


async def _no_subdomains() -> subdomains.Found:
    return subdomains.Found(gaps=(_NO_SUBDOMAINS,))


async def _quiet(_: str) -> None:
    return None


def clean_domain(text: str) -> str:
    """Accept a domain however it is pasted: a URL, an address, trailing dots, capitals."""
    value = text.strip().lower()
    value = value.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    value = value.strip(".").removeprefix("www.")
    if not value or "." not in value or any(c.isspace() for c in value):
        raise ValueError(f"not a domain: {text!r}")
    return value.encode("idna").decode("ascii")
