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
# How far below a service's own SPF record its published ranges are read.
MAX_PUBLISHED_DEPTH = 3

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


async def collect(ctx: Context, where: str, ranges: list[tuple[str, Evidence]]) -> Observed:
    networks = [(r, e, n) for r, e in ranges if (n := _network(r))]
    if not networks:
        return Observed()
    published, gaps = await published_ranges(ctx)
    claims: list[Claim] = []
    rest: list[tuple[str, Evidence, Network, frozenset[str]]] = []
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
    if dropped := len(rest) - len(picked):
        asked = f"network owners of the IP ranges in SPF at {where}"
        happened = f"{dropped} of {len(rest)} not looked up: only the first {MAX_RANGES} were (cap)"
        gaps += (Gap(asked, happened),)
    owners = await asyncio.gather(*(range_owner(ctx, n) for _, _, n, _ in picked))
    unknowns: list[Unknown] = []
    failed: list[str] = []
    for (cidr, evidence, network, candidates), announced in zip(picked, owners, strict=True):
        listed = f"; listed by {' and '.join(sorted(candidates))}" if candidates else ""
        single = network.prefixlen == network.max_prefixlen
        what = "IP address in SPF" if single else "IP range in SPF"
        if announced is None:
            failed.append(cidr)
            unknowns.append(Unknown(what, f"{cidr} (network lookup failed{listed})", where))
            continue
        asn, name = announced
        service = ctx.catalog.network(asn) or _named_in(name, candidates)
        if service:
            noted = replace(evidence, value=f"{evidence.value} (network {asn}, {name})")
            claims.append(Claim(service, Kind.SPF_NETWORK, where, noted))
            continue
        if not asn:
            unknowns.append(Unknown(what, f"{cidr} (no one network announces it{listed})", where))
            continue
        label = ctx.catalog.clouds.get(asn) or name or "owner name not published"
        unknowns.append(Unknown(what, f"{cidr} ({asn}, {label}{listed})", where))
    if failed:
        asked = f"network owners: Team Cymru TXT for {', '.join(failed)}"
        gaps += (Gap(asked, "lookup failed"),)
    return Observed(tuple(claims), tuple(unknowns), gaps=gaps)


async def range_owner(ctx: Context, network: Network) -> tuple[str, str] | None:
    """The network that announces most of a range: (ASN, owner name), ("", "") when no one
    network announces most of it, or None when a lookup failed. A large range can hold blocks
    announced by others: 149.72.0.0/16 is SendGrid's, but its first /24 is announced by Amazon.
    So a range wider than one routed block (an IPv4 /24, an IPv6 /48) is sampled at three points
    and the majority wins."""
    size = network.num_addresses
    block = 24 if network.version == 4 else 48
    points = [1] if network.prefixlen >= block else [1, size // 2 + 1, 3 * size // 4 + 1]
    found = await asyncio.gather(*(owner(ctx, network[p % size]) for p in points))
    samples = [s for s in found if s is not None]
    if len(samples) < len(found):
        return None
    asn, name = Counter(samples).most_common(1)[0][0]
    return (asn, name) if sum(1 for s in samples if s[0] == asn) * 2 > len(samples) else ("", "")


async def owner(
    ctx: Context, ip: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> tuple[str, str] | None:
    """(ASN, owner name) for an address, ("", "") when no network announces it, or None when a
    lookup failed. IPv4 asks origin.asn.cymru.com by reversed octets; IPv6 asks
    origin6.asn.cymru.com by reversed nibbles."""
    if ip.version == 4:
        origin_name = ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"
    else:
        origin_name = ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    origin = await ctx.dns.txt(origin_name)
    if not origin.answered:
        return None
    if not origin.ok:
        return "", ""
    asn = "AS" + origin.records[0].split("|")[0].split()[0]
    about = await ctx.dns.txt(f"{asn}.asn.cymru.com")
    if not about.answered:
        return None
    name = about.records[0].split("|")[-1].strip() if about.ok else ""
    return asn, name


def _network(cidr: str) -> Network | None:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


# ---------------------------------------------------------------- published ranges


async def published_ranges(ctx: Context) -> tuple[dict[Network, frozenset[str]], tuple[Gap, ...]]:
    """{network: the services that publish it}, read from every service's own SPF record through
    this map's lookups, and a gap for each service whose ranges could not all be read."""
    # A hosted SPF service's own record is its company mail, not its customers' senders.
    sources = [
        (name, host)
        for name, hosts in ctx.catalog.spf_sources().items()
        if not ctx.catalog.is_hosted_spf(name)
        for host in hosts
    ]
    found = await asyncio.gather(*(_ranges_of(ctx, host, name, 0) for name, host in sources))
    owners: dict[Network, set[str]] = {}
    problems: dict[tuple[str, str], None] = {}
    for (name, _), (networks, missed) in zip(sources, found, strict=True):
        for network in networks:
            owners.setdefault(network, set()).add(name)
        problems.update(dict.fromkeys((name, problem) for problem in missed))
    gaps = tuple(Gap(f"published ranges: SPF of {name}", why) for name, why in problems)
    return {network: frozenset(names) for network, names in owners.items()}, gaps


async def _ranges_of(
    ctx: Context, host: str, owner: str, depth: int
) -> tuple[list[Network], tuple[str, ...]]:
    """The ranges a service's record authorizes, and what kept any of them from being read."""
    if depth > MAX_PUBLISHED_DEPTH:
        return [], (f"includes more than {MAX_PUBLISHED_DEPTH} levels deep not read (cap)",)
    answer = await ctx.dns.txt(host)
    if not answer.answered:
        return [], ("lookup failed",)
    records = spf_records(answer)
    if len(records) != 1:
        return [], ()
    found: list[Network] = []
    nested: list[str] = []
    for term in terms(records[0]):
        if not term.authorizes:
            continue
        if term.mechanism in ("ip4", "ip6") and (network := _network(term.value)):
            found.append(network)
        elif _follows(term.mechanism, term.value) and ctx.catalog.spf(term.value) in (None, owner):
            nested.append(term.value)  # another service's ranges stay theirs
    missed: tuple[str, ...] = ()
    for more, problems in await asyncio.gather(
        *(_ranges_of(ctx, n, owner, depth + 1) for n in nested)
    ):
        found += more
        missed += problems
    return found, missed


def _published_by(network: Network, published: dict[Network, frozenset[str]]) -> frozenset[str]:
    """The services whose published range holds this one, judged at the most specific holding
    range. More than one means the range is shared, and the network owner decides."""
    holders = [(p.prefixlen, names) for p, names in published.items() if _inside(network, p)]
    return max(holders, key=lambda h: h[0])[1] if holders else frozenset()


def _inside(network: Network, outer: Network) -> bool:
    """Whether `network` lies within `outer`; a range never lies within the other version's."""
    if isinstance(network, ipaddress.IPv4Network):
        return isinstance(outer, ipaddress.IPv4Network) and network.subnet_of(outer)
    return isinstance(outer, ipaddress.IPv6Network) and network.subnet_of(outer)


def _named_in(owner: str, candidates: frozenset[str]) -> str | None:
    """The one candidate whose name the network owner carries: 74.125.0.0/16 is listed by Google
    Workspace and HubSpot, and announced by "GOOGLE - Google LLC"."""
    owner_words = set(owner.lower().replace(",", " ").split())
    named = [c for c in candidates if c.split()[0].lower() in owner_words]
    return named[0] if len(named) == 1 else None


def _follows(mechanism: str, value: str) -> bool:
    return mechanism in ("include", "redirect") and bool(value) and "%{" not in value
