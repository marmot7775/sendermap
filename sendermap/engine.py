"""Runs every source against a domain and assembles the map.

Two phases. The first reads what needs no prior knowledge: MX, SPF, tokens, report addresses,
labels, the website, sending subdomains. The second uses it: DKIM names a generic selector after
a service SPF or MX already shows; the networks source looks up the IP ranges the SPF walk found;
each sending subdomain gets its own smaller scan, ranked by its own MX and SPF.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import httpx

from . import catalog as catalog_module
from . import setup as setup_module
from . import story as story_module
from .dns import Lookups, Resolver, SystemResolver
from .infer import backed_selectors, services
from .model import (
    Claim,
    CtStatus,
    CtSummary,
    Evidence,
    Finding,
    Gap,
    GapKind,
    Kind,
    Observed,
    Run,
    SenderMap,
    Severity,
)
from .reconcile import with_claimed
from .selectors import Rule, probe_order, rank_rules
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
    spf_checks,
    subdomains,
    tokens,
    web,
)

Progress = Callable[[str], Awaitable[None]]
MAX_SUBDOMAINS = 30
# DKIM names probed per sending subdomain, besides the ones its own SPF, MX or delegation backs.
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
    claimed: Sequence[str] = (),
) -> SenderMap:
    """Map the services that send email as `domain`, with the evidence for each.

    `checked_at` is the moment the map is dated by, timezone-aware; the caller says when, so the
    same DNS answers and the same moment give the same map. Certificate logs are read once per
    map, Cert Spotter for the subdomain search and, with `use_ct`, crt.sh too, each cached for a
    day in `ct_cache` (None: no cache). `use_ct` also resolves every logged name and matches it.
    `claimed` is the services the client says they use, by any name; the map's reconciliation
    holds them against what it found, and is None when nothing was claimed. It asks nothing.
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
        rules = ctx.catalog.rules
        say = progress or _quiet

        if missing := await _no_domain(ctx, started):
            await say("Done")
            return with_claimed(missing, claimed, ctx.catalog)

        await say("Reading MX, SPF, DMARC and the website")
        async with asyncio.TaskGroup() as tg:
            spf_task = tg.create_task(spf.collect(ctx, domain))
            evidence = [
                tg.create_task(_guard(source, what, kind))
                for source, what, kind in (
                    (mx.collect(ctx, domain), "MX", GapKind.MX),
                    (tokens.collect(ctx), "verification tokens", GapKind.TOKENS),
                    (reports.collect(ctx), "report addresses", GapKind.REPORTS),
                    (labels.collect(ctx, domain), "bounce and tracking CNAMEs", GapKind.LABELS),
                    (mta_sts.collect(ctx), "the MTA-STS policy", GapKind.MTA_STS),
                    (
                        web.collect(ctx) if use_web else _skipped(_NO_WEB),
                        "the website",
                        GapKind.WEBSITE,
                    ),
                )
            ]
            logo_task = tg.create_task(bimi.logo(ctx))
            reads_logs = use_subdomains or use_ct
            logs_task = tg.create_task(_logs(ctx, ct_cache, use_ct) if reads_logs else _no_logs())
            subs_task = tg.create_task(
                _discover(ctx, logs_task) if use_subdomains else _no_subdomains()
            )
            ct_task = tg.create_task(
                _certificates(ctx, logs_task) if use_ct else _ct_off(logs_task)
            )
        found, tree = spf_task.result()
        logged, ct_summary = ct_task.result()
        discovered = subs_task.result()
        apex = sum((task.result() for task in evidence), found) + logs_task.result().observed
        apex += Observed(discovered.delegations, gaps=discovered.gaps)
        logo = logo_task.result()

        await say("Scanning DKIM keys and the networks in SPF")
        backed = backed_selectors(apex.claims, ctx.catalog)
        selectors = await _probe_order(ctx, rules, domain, tree.includes, backed)
        deep = await asyncio.gather(
            dkim.collect(ctx, domain, selectors, backed),
            networks.collect(ctx, domain, tree.ranges),
        )

        picked, capped = _capped(discovered.sending)
        apex += capped
        await say(f"Checking {len(picked)} sending subdomains")
        under = await asyncio.gather(
            *(_subdomain(ctx, rules, name, discovered.delegations) for name in picked)
        )

        observed = sum((*deep, *(found for found, _ in under)), apex) + logged
        partial = [p for p in (_partial(domain, tree, deep[1]), *(p for _, p in under)) if p]
        if partial:
            await say(f"Evaluating SPF at {len(partial)} name{'s' if len(partial) > 1 else ''}")
            observed += await _guard(
                spf_checks.collect(ctx, partial, observed.claims), "SPF evaluation", GapKind.SPF
            )
        checked = observed.checked_by_name()
        absences = tuple(dict.fromkeys(observed.absences))
        gaps = tuple(dict.fromkeys(observed.gaps))
        mapped, setup_findings = setup_module.build(
            services(observed.claims, ctx.catalog, domain),
            ctx.catalog,
            domain=domain,
            reads=observed.reads,
            checked=checked,
            absences=absences,
            gaps=gaps,
        )
        result = SenderMap(
            domain=domain,
            services=mapped,
            run=Run(
                checked_at=checked_at,
                elapsed=round(time.perf_counter() - started, 2),
                lookups=ctx.dns.count,
                resolver=ctx.dns.name,
            ),
            findings=_sorted(
                observed.findings
                + _cross_findings(ctx, observed)
                + dkim.same_keys(observed.keys)
                + setup_findings
            ),
            unknowns=tuple(dict.fromkeys(observed.unknowns)),
            gaps=gaps,
            subdomains_checked=tuple(picked),
            checked=checked,
            ct=ct_summary,
            historical=tuple(dict.fromkeys(observed.historical)),
            logo=logo,
            absences=absences,
        )
        result = replace(result, story=story_module.write(result))
        await say("Done")
        return with_claimed(result, claimed, ctx.catalog)


def _capped(sending: tuple[str, ...]) -> tuple[tuple[str, ...], Observed]:
    """The sending subdomains within the cap, and the gap for those past it."""
    picked = sending[:MAX_SUBDOMAINS]
    if not (dropped := len(sending) - len(picked)):
        return picked, Observed()
    happened = (
        f"{dropped} of {len(sending)} not checked: only the first {MAX_SUBDOMAINS} in "
        "alphabetical order were (cap)"
    )
    gap = Gap("sending subdomains", happened, GapKind.SUBDOMAINS, dropped, MAX_SUBDOMAINS)
    return picked, Observed(gaps=(gap,))


async def _no_domain(ctx: Context, started: float) -> SenderMap | None:
    """The map of a domain DNS says does not exist, read from its MX answer, which the MX source
    reuses from the cache otherwise: its one finding and the story that says so. None for a
    domain that exists, or when the MX source breaks (the full run then records the gap)."""
    received = await _guard(mx.collect(ctx, ctx.domain), "MX", GapKind.MX)
    if not any(f.title == mx.NO_DOMAIN for f in received.findings):
        return None
    result = SenderMap(
        domain=ctx.domain,
        services=(),
        run=Run(
            checked_at=ctx.checked_at,
            elapsed=round(time.perf_counter() - started, 2),
            lookups=ctx.dns.count,
            resolver=ctx.dns.name,
        ),
        findings=received.findings,
    )
    return replace(result, story=story_module.write(result))


async def _subdomain(
    ctx: Context, rules: tuple[Rule, ...], name: str, delegations: Iterable[Claim]
) -> tuple[Observed, spf_checks.Partial | None]:
    (found, tree), received = await asyncio.gather(spf.collect(ctx, name), mx.collect(ctx, name))
    first = found + received + Observed(tuple(c for c in delegations if c.where == name))
    backed = backed_selectors(first.claims, ctx.catalog)
    order = await _probe_order(ctx, rules, name, tree.includes, backed)
    probed = (*order[:SUBDOMAIN_PROBES], *backed)
    keys, owned = await asyncio.gather(
        dkim.collect(ctx, name, probed, backed),
        networks.collect(ctx, name, tree.ranges),
    )
    budget = Observed()
    swept = not any(a.happened.startswith(dkim.NO_SELECTORS) for a in keys.absences)
    if swept and (unasked := len(set(order) - set(probed))):
        happened = (
            f"{unasked} of {len(order)} not asked: only the first {SUBDOMAIN_PROBES} and the "
            "names its own SPF, MX or delegation backs were (cap)"
        )
        gap = Gap(f"DKIM selectors at {name}", happened, GapKind.DKIM, unasked, SUBDOMAIN_PROBES)
        budget = Observed(gaps=(gap,))
    return first + keys + owned + budget, _partial(name, tree, owned)


def _partial(where: str, tree: spf.SpfTree, owned: Observed) -> spf_checks.Partial | None:
    """Why SPF at `where` needs evaluating, or None when the walk named everything it
    authorizes: a hosted or macro record, links past the depth cap, or a flattened record whose
    ranges the networks source (`owned`) left unknown."""
    if why := tree.unnamed:
        return spf_checks.Partial(where, why)
    unknown = sum(u.where == where and u.what in networks.RANGE_KINDS for u in owned.unknowns)
    if tree.flattened and unknown:
        ranges = f"{unknown} range{'s' if unknown > 1 else ''}"
        return spf_checks.Partial(where, f"flattened by {tree.flattened[0]}, {ranges} unknown")
    return None


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


_NO_WEB = Gap("the website", "not read: web checks were turned off (--no-web)", GapKind.OFF)
_NO_SUBDOMAINS = Gap(
    "sending subdomains",
    "not searched: subdomain checks were turned off (--no-subdomains)",
    GapKind.OFF,
)


async def _guard(source: Awaitable[Observed], what: str, kind: GapKind) -> Observed:
    """Run one source; if it breaks, record a gap instead of losing the whole map."""
    try:
        return await source
    except Exception as e:  # a source bug must not take down every other source
        return Observed(gaps=(Gap(what, f"the check crashed: {type(e).__name__}", kind),))


async def _logs(ctx: Context, cache: Path | None, expired: bool) -> ct.Logs:
    """The certificate logs, read once; a crash here costs the logged names, not the map."""
    try:
        return await ct.read_logs(ctx, cache, expired=expired)
    except Exception as e:  # a source bug must not take down every other source
        crashed = Gap(
            "certificate transparency",
            f"the check crashed: {type(e).__name__}",
            GapKind.CERTIFICATE_LOG,
        )
        return ct.Logs(observed=Observed(gaps=(crashed,)))


async def _no_logs() -> ct.Logs:
    return ct.Logs()


async def _discover(ctx: Context, logs: Awaitable[ct.Logs]) -> subdomains.Found:
    """Sending subdomains; a crash here costs the subdomains, not the map, and says so."""
    try:
        return await subdomains.discover(ctx, (logged.name for logged in (await logs).names))
    except Exception as e:  # a source bug must not take down every other source
        crashed = Gap(
            "sending subdomains", f"the search crashed: {type(e).__name__}", GapKind.SUBDOMAINS
        )
        return subdomains.Found(gaps=(crashed,))


async def _certificates(ctx: Context, logs: Awaitable[ct.Logs]) -> tuple[Observed, CtSummary]:
    """The logged names resolved and matched; a crash here costs CT, not the map, and says so."""
    read = await logs
    try:
        return await ct.collect(ctx, read)
    except Exception as e:  # a source bug must not take down every other source
        crashed = Gap(
            "certificate transparency",
            f"the check crashed: {type(e).__name__}",
            GapKind.CERTIFICATE_LOG,
        )
        return Observed(gaps=(crashed,)), CtSummary(CtStatus.UNAVAILABLE, providers=read.providers)


async def _ct_off(logs: Awaitable[ct.Logs]) -> tuple[Observed, CtSummary]:
    read = await logs
    return Observed(), CtSummary(logged=len(read.names), providers=read.providers)


async def _skipped(gap: Gap) -> Observed:
    return Observed(gaps=(gap,))


async def _no_subdomains() -> subdomains.Found:
    return subdomains.Found(gaps=(_NO_SUBDOMAINS,))


async def _quiet(_: str) -> None:
    return None


# One label of a hostname once IDNA-encoded (RFC 1123 section 2.1), and a top-level domain,
# which is never all digits, so an IPv4 address is not taken for a domain.
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(?=.*[a-z])[a-z0-9-]+$")


def clean_domain(text: str) -> str:
    """Accept a domain however it is pasted: a URL, an address, trailing dots, capitals. Refuse
    an IP address, a wildcard, and anything that is not a hostname."""
    value = text.strip().lower()
    value = value.split("://", 1)[-1].split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    value = value.strip(".").removeprefix("www.")
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_name = ""
    labels = ascii_name.split(".")
    if (
        len(labels) < 2
        or len(ascii_name) > 253
        or not all(_LABEL.match(label) for label in labels)
        or not _TLD.match(labels[-1])
    ):
        raise ValueError(f"not a domain: {text!r}")
    return ascii_name
