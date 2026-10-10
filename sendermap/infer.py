"""From claims to the map: group by service, rank by the strongest evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .catalog import Catalog
from .model import Claim, Kind, Role, Service, Tier


def services(claims: Iterable[Claim], catalog: Catalog) -> tuple[Service, ...]:
    grouped: defaultdict[str, list[Claim]] = defaultdict(list)
    for claim in dict.fromkeys(claims):  # drop repeats, keep order
        grouped[claim.service].append(claim)
    return tuple(
        sorted((_service(name, found, catalog) for name, found in grouped.items()), key=_order)
    )


def _service(name: str, claims: list[Claim], catalog: Catalog) -> Service:
    tiers = [tier for c in claims if (tier := c.kind.tier)]
    return Service(
        name=name,
        category=catalog.category(name),
        tier=min(tiers, key=lambda t: t.rank) if tiers else Tier.ACCOUNT_ONLY,
        role=Role.SENDER if tiers else Role.REPORTING,
        claims=tuple(sorted(claims, key=_strength)),
    )


def _strength(claim: Claim) -> tuple[int, int]:
    tier = claim.kind.tier
    return (tier.rank if tier else len(Tier), list(Kind).index(claim.kind))


def _order(service: Service) -> tuple[bool, int, str]:
    return (service.role is Role.REPORTING, service.tier.rank, service.name.lower())


def backed_selectors(claims: Iterable[Claim], catalog: Catalog) -> dict[str, str]:
    """{selector: service} for services that SPF or MX already show, so a generic selector name
    on their list counts as theirs. The first service to claim a name keeps it."""
    backed: dict[str, str] = {}
    for claim in claims:
        if claim.kind in (Kind.MX, Kind.SPF_INCLUDE, Kind.SPF_NETWORK):
            for selector in sorted(catalog.selectors_of(claim.service)):
                backed.setdefault(selector, claim.service)
    return backed
