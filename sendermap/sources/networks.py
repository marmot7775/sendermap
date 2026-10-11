"""Who is behind the IP ranges a domain lists in SPF.

Many records name raw addresses instead of a service's include, often because a tool flattened
the record. Each range, IPv4 or IPv6, is named in this order:

1. Published ranges. Each service publishes its sending ranges in its own SPF record. A range
   inside a range that exactly one service publishes is that service: this is how a flattened
   copy of Amazon SES's ranges is recognised. When several services publish the holding range,
   this check names none of them.
2. The networks that announce the address. Team Cymru's public IP to ASN mapping, served over
   DNS, says whose network it is. An address can be announced from more than one network (Amazon
   answers from AS16509 and AS14618), and the answers are a set, so all of them are read. The
   range goes to a service only when vendors.json lists every one of those networks as that
   service's own (Mailchimp, SendGrid, Mailgun and a few others run their own).
3. Anything else is listed as unknown, with the network, the cloud's name when vendors.json
   lists the network as a shared cloud, and the services that publish the range, if any. A
   cloud is never credited to a service: 74.125.0.0/16 is published by both Google Workspace
   and HubSpot and announced by Google's network, which vendors.json lists as a cloud, so it is
   unknown, listed by both. When the networks are not all one service's, nothing is asserted
   that only one answer shows: the range is unknown and names every network and its owner.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass

from ..model import Claim, Evidence, Gap, Kind, Observed, Unknown
from . import Context
from .spf import spf_records, terms

MAX_RANGES = 24
# How far below a service's own SPF record its published ranges are read.
MAX_PUBLISHED_DEPTH = 3

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
# {network: {service: the term in that service's own SPF record that publishes it}}
Published = dict[Network, dict[str, Evidence]]


@dataclass(frozen=True, slots=True)
class Owner:
    """Who announces an address or range: each network as (ASN, its owner's name or ""), in ASN
    order, none when no network does, and the Team Cymru answers that say so."""

    networks: tuple[tuple[str, str], ...]
    evidence: tuple[Evidence, ...]

    @property
    def asns(self) -> tuple[str, ...]:
        return tuple(asn for asn, _ in self.networks)


def credited(ctx: Context, announced: Owner) -> str | None:
    """The service every announcing network belongs to, or None when any does not."""
    services = {ctx.catalog.network(asn) for asn in announced.asns}
    return services.pop() if len(services) == 1 else None


def announced_by(ctx: Context, announced: Owner) -> str:
    """The networks in words, each with the cloud vendors.json names it as or its owner's name,
    networks under one name together: "AS14618 and AS16509, Amazon Web Services"."""
    labels: dict[str, list[str]] = {}
    for asn, name in announced.networks:
        label = ctx.catalog.clouds.get(asn) or name or "owner name not published"
        labels.setdefault(label, []).append(asn)
    return "; ".join(f"{' and '.join(asns)}, {label}" for label, asns in labels.items())


async def collect(ctx: Context, where: str, ranges: list[tuple[str, Evidence]]) -> Observed:
    networks = [(r, e, n) for r, e in ranges if (n := _network(r))]
    if not networks:
        return Observed()
    published, gaps = await published_ranges(ctx)
    claims: list[Claim] = []
    rest: list[tuple[str, Evidence, Network, frozenset[str]]] = []
    for cidr, evidence, network in networks:
        candidates = published_by(network, published)
        if len(candidates) == 1:
            ((publisher, source),) = candidates.items()
            claims.append(Claim(publisher, Kind.SPF_NETWORK, where, evidence, (source,)))
        else:
            rest.append((cidr, evidence, network, frozenset(candidates)))
    picked = rest[:MAX_RANGES]
    if dropped := len(rest) - len(picked):
        asked = f"network owners of the IP ranges in SPF at {where}"
        happened = f"{dropped} of {len(rest)} not looked up: only the first {MAX_RANGES} were (cap)"
        gaps += (Gap(asked, happened),)
    owners = await asyncio.gather(*(range_owner(ctx, n) for _, _, n, _ in picked))
    unknowns: list[Unknown] = []
    failed: list[str] = []
    for (cidr, evidence, network, listers), announced in zip(picked, owners, strict=True):
        listed = f"; listed by {' and '.join(sorted(listers))}" if listers else ""
        single = network.prefixlen == network.max_prefixlen
        what = "IP address in SPF" if single else "IP range in SPF"
        if announced is None:
            failed.append(cidr)
            value = f"{cidr} (network lookup failed{listed})"
            unknowns.append(Unknown(what, value, where, evidence))
            continue
        if service := credited(ctx, announced):
            claims.append(Claim(service, Kind.SPF_NETWORK, where, evidence, announced.evidence))
            continue
        if not announced.networks:
            value = f"{cidr} (no one network announces it{listed})"
            unknowns.append(Unknown(what, value, where, evidence))
            continue
        value = f"{cidr} ({announced_by(ctx, announced)}{listed})"
        unknowns.append(Unknown(what, value, where, evidence))
    if failed:
        asked = f"network owners: Team Cymru TXT for {', '.join(failed)}"
        gaps += (Gap(asked, "lookup failed"),)
    return Observed(tuple(claims), tuple(unknowns), gaps=gaps)


async def range_owner(ctx: Context, network: Network) -> Owner | None:
    """The networks that announce most of a range, with the answers for the samples that show
    them; an Owner with no networks when no network announces most of it; None when a lookup
    failed. A large range can hold blocks announced by others: 149.72.0.0/16 is SendGrid's, but
    its first /24 is announced by Amazon. So a range wider than one routed block (an IPv4 /24, an
    IPv6 /48) is sampled at three points, and of the union of the networks the samples return,
    those announcing a majority of the samples are kept."""
    size = network.num_addresses
    block = 24 if network.version == 4 else 48
    points = [1] if network.prefixlen >= block else [1, size // 2 + 1, 3 * size // 4 + 1]
    found = await asyncio.gather(*(owner(ctx, network[p % size]) for p in points))
    samples = [s for s in found if s is not None]
    if len(samples) < len(found):
        return None
    union = sorted({n for s in samples for n in s.networks}, key=_asn_order)
    kept = tuple(n for n in union if sum(n in s.networks for s in samples) * 2 > len(samples))
    if not kept:
        return Owner((), tuple(dict.fromkeys(e for s in samples for e in s.evidence)))
    agree = [s for s in samples if set(kept) & set(s.networks)]
    return Owner(kept, tuple(dict.fromkeys(e for s in agree for e in s.evidence)))


async def owner(ctx: Context, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Owner | None:
    """Who announces an address: every origin network Team Cymru answers with, each named; an
    Owner with no networks when no network does; None when a lookup failed. IPv4 asks
    origin.asn.cymru.com by reversed octets; IPv6 asks origin6.asn.cymru.com by reversed nibbles.
    The evidence is every answer read."""
    if ip.version == 4:
        origin_name = ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"
    else:
        origin_name = ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    origin = await ctx.dns.txt(origin_name)
    if not origin.answered:
        return None
    if not origin.ok:
        return Owner((), (Evidence(origin_name, "TXT", origin.status.value, ctx.checked_at),))
    # One answer per announced prefix, and one answer may list several origins.
    asns = sorted(
        {"AS" + n for r in origin.records for n in r.split("|")[0].split() if n.isdigit()},
        key=lambda asn: int(asn[2:]),
    )
    said = [Evidence(origin_name, "TXT", r, ctx.checked_at) for r in origin.records]
    abouts = await asyncio.gather(*(ctx.dns.txt(f"{asn}.asn.cymru.com") for asn in asns))
    if not all(a.answered for a in abouts):
        return None
    named = [(a, a.records[0]) for a in abouts if a.ok]
    owners = tuple(
        (asn, a.records[0].split("|")[-1].strip() if a.ok else "")
        for asn, a in zip(asns, abouts, strict=True)
    )
    evidence = said + [Evidence(a.name, "TXT", r, ctx.checked_at) for a, r in named]
    return Owner(owners, tuple(evidence))


def _asn_order(network: tuple[str, str]) -> tuple[int, str]:
    return (int(network[0][2:]), network[1])


def _network(cidr: str) -> Network | None:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


# ---------------------------------------------------------------- published ranges


async def published_ranges(ctx: Context) -> tuple[Published, tuple[Gap, ...]]:
    """{network: {service: the term that publishes it}}, read from every service's own SPF
    record through this map's lookups, and a gap for each service whose ranges could not all be
    read."""
    # A hosted SPF service's own record is its company mail, not its customers' senders.
    sources = [
        (name, host)
        for name, hosts in ctx.catalog.spf_sources().items()
        if not ctx.catalog.is_hosted_spf(name)
        for host in hosts
    ]
    found = await asyncio.gather(*(_ranges_of(ctx, host, name, 0) for name, host in sources))
    owners: Published = {}
    problems: dict[tuple[str, str], None] = {}
    for (name, _), (networks, missed) in zip(sources, found, strict=True):
        for network, evidence in networks:
            owners.setdefault(network, {}).setdefault(name, evidence)
        problems.update(dict.fromkeys((name, problem) for problem in missed))
    gaps = tuple(Gap(f"published ranges: SPF of {name}", why) for name, why in problems)
    return owners, gaps


async def _ranges_of(
    ctx: Context, host: str, owner: str, depth: int
) -> tuple[list[tuple[Network, Evidence]], tuple[str, ...]]:
    """The ranges a service's record authorizes, and what kept any of them from being read."""
    if depth > MAX_PUBLISHED_DEPTH:
        return [], (f"includes more than {MAX_PUBLISHED_DEPTH} levels deep not read (cap)",)
    answer = await ctx.dns.txt(host)
    if not answer.answered:
        return [], ("lookup failed",)
    records = spf_records(answer)
    if len(records) != 1:
        return [], ()
    found: list[tuple[Network, Evidence]] = []
    nested: list[str] = []
    for term in terms(records[0]):
        if not term.authorizes:
            continue
        if term.mechanism in ("ip4", "ip6") and (network := _network(term.value)):
            listed = Evidence(answer.name, "TXT", f"{term.mechanism}:{term.value}", ctx.checked_at)
            found.append((network, listed))
        elif _follows(term.mechanism, term.value) and ctx.catalog.spf(term.value) in (None, owner):
            nested.append(term.value)  # another service's ranges stay theirs
    missed: tuple[str, ...] = ()
    for more, problems in await asyncio.gather(
        *(_ranges_of(ctx, n, owner, depth + 1) for n in nested)
    ):
        found += more
        missed += problems
    return found, missed


def published_by(network: Network, published: Published) -> dict[str, Evidence]:
    """{service: the term that publishes it} for the services whose published range holds this
    one, judged at the most specific holding range. More than one means the range is shared,
    and the network owner decides."""
    holders = [(p.prefixlen, names) for p, names in published.items() if _inside(network, p)]
    return max(holders, key=lambda h: h[0])[1] if holders else {}


def _inside(network: Network, outer: Network) -> bool:
    """Whether `network` lies within `outer`; a range never lies within the other version's."""
    if isinstance(network, ipaddress.IPv4Network):
        return isinstance(outer, ipaddress.IPv4Network) and network.subnet_of(outer)
    return isinstance(outer, ipaddress.IPv6Network) and network.subnet_of(outer)


def _follows(mechanism: str, value: str) -> bool:
    return mechanism in ("include", "redirect") and bool(value) and "%{" not in value
