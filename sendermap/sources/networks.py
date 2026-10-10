"""Who is behind the IP ranges a domain lists in SPF.

Many records name raw addresses instead of a service's include, often because a tool flattened
the record. Two checks name them:

1. Published ranges. Each service publishes its sending ranges in its own SPF record. A range
   inside one of them is that service, exactly: this is how a flattened copy of Amazon SES's or
   Google Workspace's ranges is recognised.
2. The network that announces the address. Mailchimp, SendGrid, Mailgun, Salesforce and others
   run their own; Team Cymru's public IP to ASN mapping, served over DNS, says whose it is.
   Shared clouds are named as clouds and never credited to a service.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections import Counter
from dataclasses import replace

from ..model import Claim, Evidence, Gap, Kind, Observed, Unknown
from . import Context
from .spf import spf_records, terms

MAX_RANGES = 24


async def collect(ctx: Context, where: str, ranges: list[tuple[str, Evidence]]) -> Observed:
    networks = [(r, e, n) for r, e in ranges if (n := _network(r))]
    if not networks:
        return Observed()
    published, gaps = await published_ranges(ctx)
    claims: list[Claim] = []
    rest: list[tuple[str, Evidence, ipaddress.IPv4Network, frozenset[str]]] = []
    for cidr, evidence, network in networks:
        candidates = _published_by(network, published)
        if len(candidates) == 1:
            (publisher,) = candidates
            noted = replace(
                evidence, value=f"{evidence.value} (inside {publisher}'s published range)"
            )
            claims.append(Claim(publisher, Kind.SPF_NETWORK, where, noted))
        else:
            rest.append((cidr, evidence, network, candidates))
    picked = rest[:MAX_RANGES]
    owners = await asyncio.gather(*(range_owner(ctx, n) for _, _, n, _ in picked))
    unknowns: list[Unknown] = []
    for (cidr, evidence, _, candidates), (asn, name) in zip(picked, owners, strict=True):
        service = ctx.catalog.network(asn) or _named_in(name, candidates)
        if service:
            noted = replace(evidence, value=f"{evidence.value} (network {asn}, {name})")
            claims.append(Claim(service, Kind.SPF_NETWORK, where, noted))
            continue
        label = ctx.catalog.clouds.get(asn) or name or "owner unknown"
        listed = f"; listed by {' and '.join(sorted(candidates))}" if candidates else ""
        what = "IP address in SPF" if cidr.endswith("/32") or "/" not in cidr else "IP range in SPF"
        unknowns.append(Unknown(what, f"{cidr} ({asn or 'no network'}, {label}{listed})", where))
    return Observed(tuple(claims), tuple(unknowns), gaps=gaps)


async def range_owner(ctx: Context, network: ipaddress.IPv4Network) -> tuple[str, str]:
    """The network that announces most of a range. A large range can hold blocks announced by
    others: 149.72.0.0/16 is SendGrid's, but its first /24 is announced by Amazon. So a range
    bigger than a /24 is sampled at three points and the majority wins."""
    size = network.num_addresses
    points = [1] if size <= 256 else [1, size // 2 + 1, 3 * size // 4 + 1]
    samples = await asyncio.gather(*(owner(ctx, str(network[p % size])) for p in points))
    asn, name = Counter(samples).most_common(1)[0][0]
    return (asn, name) if sum(1 for s in samples if s[0] == asn) * 2 > len(samples) else ("", "")


async def owner(ctx: Context, ip: str) -> tuple[str, str]:
    """(ASN, owner name) for an IPv4 address, or ("", "") when unknown."""
    reverse = ".".join(reversed(ip.split(".")))
    origin = await ctx.dns.txt(f"{reverse}.origin.asn.cymru.com")
    if not origin.ok:
        return "", ""
    asn = "AS" + origin.records[0].split("|")[0].split()[0]
    about = await ctx.dns.txt(f"{asn}.asn.cymru.com")
    name = about.records[0].split("|")[-1].strip() if about.ok else ""
    return asn, name


def _network(cidr: str) -> ipaddress.IPv4Network | None:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    return network if isinstance(network, ipaddress.IPv4Network) else None


# ---------------------------------------------------------------- published ranges


async def published_ranges(
    ctx: Context,
) -> tuple[dict[ipaddress.IPv4Network, frozenset[str]], tuple[Gap, ...]]:
    """{network: the services that publish it}, read from every service's own SPF record through
    this map's lookups, and a gap for each service whose ranges could not be read."""
    # A hosted SPF service's own record is its company mail, not its customers' senders.
    sources = [
        (name, host)
        for name, hosts in ctx.catalog.spf_sources().items()
        if not ctx.catalog.is_hosted_spf(name)
        for host in hosts
    ]
    found = await asyncio.gather(*(_ranges_of(ctx, host, name, 0) for name, host in sources))
    owners: dict[ipaddress.IPv4Network, set[str]] = {}
    unread: list[str] = []
    for (name, _), (networks, complete) in zip(sources, found, strict=True):
        for network in networks:
            owners.setdefault(network, set()).add(name)
        if not complete and name not in unread:
            unread.append(name)
    gaps = tuple(Gap(f"the published ranges of {name}", "lookups failed") for name in unread)
    return {network: frozenset(names) for network, names in owners.items()}, gaps


async def _ranges_of(
    ctx: Context, host: str, owner: str, depth: int
) -> tuple[list[ipaddress.IPv4Network], bool]:
    """The IPv4 ranges a service's record authorizes, and whether every lookup answered."""
    if depth > 3:
        return [], True
    answer = await ctx.dns.txt(host)
    if not answer.answered:
        return [], False
    records = spf_records(answer)
    if len(records) != 1:
        return [], True
    found: list[ipaddress.IPv4Network] = []
    nested: list[str] = []
    for term in terms(records[0]):
        if not term.authorizes:
            continue
        if term.mechanism == "ip4" and (network := _network(term.value)):
            found.append(network)
        elif _follows(term.mechanism, term.value) and ctx.catalog.spf(term.value) in (None, owner):
            nested.append(term.value)  # another service's ranges stay theirs
    complete = True
    for more, answered in await asyncio.gather(
        *(_ranges_of(ctx, n, owner, depth + 1) for n in nested)
    ):
        found += more
        complete = complete and answered
    return found, complete


def _published_by(
    network: ipaddress.IPv4Network, published: dict[ipaddress.IPv4Network, frozenset[str]]
) -> frozenset[str]:
    """The services whose published range holds this one, judged at the most specific holding
    range. More than one means the range is shared, and the network owner decides."""
    holders = [(p.prefixlen, names) for p, names in published.items() if network.subnet_of(p)]
    return max(holders, key=lambda h: h[0])[1] if holders else frozenset()


def _named_in(owner: str, candidates: frozenset[str]) -> str | None:
    """The one candidate whose name the network owner carries: 74.125.0.0/16 is listed by Google
    Workspace and HubSpot, and announced by "GOOGLE - Google LLC"."""
    owner_words = set(owner.lower().replace(",", " ").split())
    named = [c for c in candidates if c.split()[0].lower() in owner_words]
    return named[0] if len(named) == 1 else None


def _follows(mechanism: str, value: str) -> bool:
    return mechanism in ("include", "redirect") and bool(value) and "%{" not in value
