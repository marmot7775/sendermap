"""From claims to the map: group by service, rank by the strongest evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .catalog import Catalog
from .model import Claim, Kind, Role, Service, Tier


def services(claims: Iterable[Claim], catalog: Catalog, domain: str) -> tuple[Service, ...]:
    grouped: defaultdict[str, list[Claim]] = defaultdict(list)
    for claim in dict.fromkeys(claims):  # drop repeats, keep order
        grouped[claim.service].append(claim)
    found = (_service(name, cs, catalog, domain) for name, cs in grouped.items())
    return tuple(sorted(found, key=_order))


def _service(name: str, claims: list[Claim], catalog: Catalog, domain: str) -> Service:
    tiers = [tier for c in claims if (tier := c.kind.tier)]
    return Service(
        name=name,
        category=catalog.category(name),
        tier=min(tiers, key=lambda t: t.rank) if tiers else None,
        role=Role.SENDER if tiers else Role.REPORTING,
        claims=tuple(sorted(claims, key=lambda c: _strength(c, domain))),
    )


def _strength(claim: Claim, domain: str) -> tuple[int, bool, int]:
    """Strongest tier first; within a tier, evidence on the domain itself before a subdomain."""
    tier = claim.kind.tier
    return (tier.rank if tier else len(Tier), claim.where != domain, list(Kind).index(claim.kind))


def _order(service: Service) -> tuple[bool, int, str]:
    rank = service.tier.rank if service.tier else len(Tier)
    return (service.role is Role.REPORTING, rank, service.name.lower())


def backed_selectors(claims: Iterable[Claim], catalog: Catalog) -> dict[str, Claim]:
    """{selector: the SPF or MX claim of a service the domain already shows}, so a generic
    selector name on that service's list counts as theirs, backed by that claim's record. The
    first service to claim a name keeps it."""
    backed: dict[str, Claim] = {}
    for claim in claims:
        if claim.kind in (Kind.MX, Kind.SUBDOMAIN_MAILBOX, Kind.SPF_INCLUDE, Kind.SPF_NETWORK):
            for selector in sorted(catalog.selectors_of(claim.service)):
                backed.setdefault(selector, claim)
    return backed
