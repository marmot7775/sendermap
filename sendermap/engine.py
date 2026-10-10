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

import httpx

from . import catalog as catalog_module
from .dns import Lookups, Resolver, SystemResolver
from .infer import backed_selectors, services
from .model import Finding, Gap, Kind, Observed, SenderMap, Severity
from .selectors import Rule, load_rules, probe_order, rank_rules
from .sources import (
    Context,
    bimi,
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
    resolver: Resolver | None = None,
    http: httpx.AsyncClient | None = None,
    use_web: bool = True,
    use_subdomains: bool = True,
    progress: Progress | None = None,
) -> SenderMap:
    """Map the services that send email as `domain`, with the evidence for each."""
    domain = clean_domain(domain)
    started = time.perf_counter()
    async with AsyncExitStack() as stack:
        if http is None and (use_web or use_subdomains):
            http = await stack.enter_async_context(httpx.AsyncClient(http2=False))
        ctx = Context(
            domain,
            Lookups(resolver or SystemResolver()),
            catalog_module.load(),
            http if (use_web or use_subdomains) else None,
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
                    (web.collect(ctx) if use_web else _nothing(), "the website"),
                )
            ]
            logo_task = tg.create_task(bimi.logo(ctx))
            subs_task = tg.create_task(_discover(ctx) if use_subdomains else _none_found())
        found, tree = spf_task.result()
        apex = sum((task.result() for task in evidence), found)
        sending_subdomains, ct_read = subs_task.result()
        logo = logo_task.result()

        await say("Scanning DKIM keys and the networks in SPF")
        backed = backed_selectors(apex.claims, ctx.catalog)
        selectors = await _probe_order(ctx, rules, domain, tree.includes, backed)
        deep = await asyncio.gather(
            dkim.collect(ctx, domain, selectors, backed),
            networks.collect(ctx, domain, tree.ranges),
        )

        picked = sending_subdomains[:MAX_SUBDOMAINS]
        await say(f"Checking {len(picked)} sending subdomains")
        under = await asyncio.gather(*(_subdomain(ctx, rules, name) for name in picked))

        observed = sum((*deep, *under), apex)
        result = SenderMap(
            domain=domain,
            services=services(observed.claims, ctx.catalog, domain),
            findings=_sorted(observed.findings + _cross_findings(ctx, observed)),
            unknowns=tuple(dict.fromkeys(observed.unknowns)),
            gaps=observed.gaps + (() if ct_read else (_ct_gap(),)),
            subdomains_checked=tuple(picked),
            logo=logo,
            lookups=ctx.dns.count,
            elapsed=round(time.perf_counter() - started, 2),
        )
        await say("Done")
        return result


async def _subdomain(ctx: Context, rules: tuple[Rule, ...], name: str) -> Observed:
    (found, tree), received = await asyncio.gather(spf.collect(ctx, name), mx.collect(ctx, name))
    first = found + received
    backed = backed_selectors(first.claims, ctx.catalog)
    order = await _probe_order(ctx, rules, name, tree.includes, backed)
    keys, owned = await asyncio.gather(
        dkim.collect(ctx, name, (*order[:SUBDOMAIN_PROBES], *backed), backed),
        networks.collect(ctx, name, tree.ranges),
    )
    return first + keys + owned


async def _probe_order(
    ctx: Context,
    rules: tuple[Rule, ...],
    where: str,
    spf_includes: Iterable[str],
    backed: Mapping[str, str],
) -> tuple[str, ...]:
    """The DKIM sweep for `where`, with the rules its own MX and SPF hint at moved first."""
    # The MX source already asked, so this query is a cache hit.
    mx_hosts = [h for r in (await ctx.dns.query(where, "MX")).records if (h := mx.exchange(r))]
    ranked = rank_rules(rules, mx_hosts, spf_includes)
    return probe_order(ranked, (*ctx.catalog.probe_selectors, *backed))


def _cross_findings(ctx: Context, observed: Observed) -> tuple[Finding, ...]:
    gateways = sorted(
        {
            c.service
            for c in observed.claims
            if c.kind is Kind.MX
            and c.where == ctx.domain
            and ctx.catalog.category(c.service) == "Security gateway"
        }
    )
    return tuple(
        Finding(
            Severity.NOTE,
            f"Mail reaches {g} before the mailbox provider",
            f"{g} filters incoming mail, so the mailbox provider behind it does not show in "
            "MX. MTA-STS, SPF and DKIM usually still name it.",
        )
        for g in gateways
    )


def _sorted(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    order = list(Severity)
    return tuple(sorted(dict.fromkeys(findings), key=lambda f: order.index(f.severity)))


def _ct_gap() -> Gap:
    return Gap(
        "certificate transparency logs", "they did not answer, so only common labels were checked"
    )


async def _guard(source: Awaitable[Observed], what: str) -> Observed:
    """Run one source; if it breaks, record a gap instead of losing the whole map."""
    try:
        return await source
    except Exception as e:  # a source bug must not take down every other source
        return Observed(gaps=(Gap(what, f"failed: {type(e).__name__}"),))


async def _discover(ctx: Context) -> tuple[list[str], bool]:
    """Sending subdomains; a failure here costs the subdomains, not the map."""
    try:
        return await subdomains.discover(ctx)
    except Exception:  # a source bug must not take down every other source
        return [], False


async def _nothing() -> Observed:
    return Observed()


async def _none_found() -> tuple[list[str], bool]:
    return [], True


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
