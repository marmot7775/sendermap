"""The shapes everything else passes around.

Sources observe facts and turn each into a Claim about one service, carrying the Evidence that
shows it. Inference groups claims into Services and ranks them. Nothing here does any I/O.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

SCHEMA = "sendermap/1"


class Tier(StrEnum):
    """How sure we are that a service sends for the domain, strongest first."""

    IN_USE = "In use"
    CONFIGURED = "Configured"
    LIKELY = "Likely"
    ACCOUNT_ONLY = "Account only"

    @property
    def rank(self) -> int:
        return list(Tier).index(self)


class Role(StrEnum):
    SENDER = "sender"
    REPORTING = "reporting"


class Kind(StrEnum):
    """What a piece of evidence shows about a service, and so how much it counts."""

    MX = "receives the domain's mail (MX)"
    SUBDOMAIN_MX = "receives replies and bounces for a sending subdomain (MX)"
    MTA_STS = "named in the MTA-STS policy"
    SPF_INCLUDE = "included in SPF"
    SPF_NETWORK = "owns a network listed in SPF"
    DKIM_CNAME = "hosts a DKIM key (CNAME)"
    DKIM_NAME = "DKIM key named for it"
    RETURN_PATH = "bounce address CNAME"
    TRACKING = "link tracking CNAME"
    WEBSITE = "script or form on the website"
    TOKEN = "verification token"
    AUTODISCOVER = "autodiscover CNAME"
    DKIM_RETIRED = "retired DKIM key"
    DKIM_DANGLING = "DKIM CNAME to a missing key"
    DMARC_REPORTS = "receives DMARC reports"
    TLSRPT_REPORTS = "receives TLS reports"

    @property
    def tier(self) -> Tier | None:
        """The tier this kind of evidence supports; None for report addresses."""
        return _KIND_TIER.get(self)


_KIND_TIER = {
    Kind.MX: Tier.IN_USE,
    Kind.MTA_STS: Tier.IN_USE,
    Kind.SUBDOMAIN_MX: Tier.CONFIGURED,
    Kind.SPF_INCLUDE: Tier.CONFIGURED,
    Kind.SPF_NETWORK: Tier.CONFIGURED,
    Kind.DKIM_CNAME: Tier.CONFIGURED,
    Kind.RETURN_PATH: Tier.CONFIGURED,
    Kind.TRACKING: Tier.CONFIGURED,
    Kind.DKIM_NAME: Tier.LIKELY,
    Kind.WEBSITE: Tier.LIKELY,
    Kind.TOKEN: Tier.ACCOUNT_ONLY,
    Kind.AUTODISCOVER: Tier.ACCOUNT_ONLY,
    Kind.DKIM_RETIRED: Tier.ACCOUNT_ONLY,
    Kind.DKIM_DANGLING: Tier.ACCOUNT_ONLY,
}

REPORT_KINDS = frozenset({Kind.DMARC_REPORTS, Kind.TLSRPT_REPORTS})


class Severity(StrEnum):
    RISK = "risk"
    WARNING = "warning"
    NOTE = "note"


@dataclass(frozen=True, slots=True)
class Evidence:
    """One observed public fact: a record at a name, or a line on a web page, and when it was
    checked (the run's checked_at)."""

    name: str
    rtype: str
    value: str
    checked_at: datetime

    def __str__(self) -> str:
        return f"{self.name} {self.rtype} {self.value}"


@dataclass(frozen=True, slots=True)
class Claim:
    """What one piece of evidence shows about one service, at one name in the domain."""

    service: str
    kind: Kind
    where: str
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    category: str
    tier: Tier
    role: Role
    claims: tuple[Claim, ...]

    @property
    def decided_by(self) -> Claim:
        """The claim that set the tier: the one a reader should check first."""
        return min(self.claims, key=_claim_strength)

    @property
    def subdomains(self) -> tuple[str, ...]:
        return tuple(sorted({c.where for c in self.claims}))


def _claim_strength(claim: Claim) -> int:
    tier = claim.kind.tier
    return tier.rank if tier else len(Tier)


@dataclass(frozen=True, slots=True)
class Unknown:
    """Something that clearly is a sender but matches no service in the catalog."""

    what: str
    value: str
    where: str


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    title: str
    detail: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class Gap:
    """A question that got no usable answer: what was asked, and what happened instead. Its
    silence says nothing, so it is never to be read as absent."""

    asked: str
    happened: str


@dataclass(frozen=True, slots=True)
class Observed:
    """What one source returns."""

    claims: tuple[Claim, ...] = ()
    unknowns: tuple[Unknown, ...] = ()
    findings: tuple[Finding, ...] = ()
    gaps: tuple[Gap, ...] = ()

    def __add__(self, other: Observed) -> Observed:
        return Observed(
            self.claims + other.claims,
            self.unknowns + other.unknowns,
            self.findings + other.findings,
            self.gaps + other.gaps,
        )


@dataclass(frozen=True, slots=True)
class Run:
    """When and how one map was made. Two runs over the same DNS answers differ here only."""

    checked_at: datetime
    elapsed: float
    lookups: int


@dataclass(frozen=True, slots=True)
class SenderMap:
    """The map of one domain. Equal maps compare equal whatever their runs."""

    domain: str
    services: tuple[Service, ...]
    run: Run = field(compare=False)
    findings: tuple[Finding, ...] = ()
    unknowns: tuple[Unknown, ...] = ()
    gaps: tuple[Gap, ...] = ()
    subdomains_checked: tuple[str, ...] = ()
    logo: str | None = None
    schema: str = field(default=SCHEMA)

    @property
    def senders(self) -> tuple[Service, ...]:
        return tuple(s for s in self.services if s.role is Role.SENDER)

    @property
    def reporting(self) -> tuple[Service, ...]:
        return tuple(s for s in self.services if s.role is Role.REPORTING)

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON values: times as ISO 8601 strings."""
        return asdict(self, dict_factory=_json_ready)


def _json_ready(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    return {k: v.isoformat() if isinstance(v, datetime) else v for k, v in pairs}
