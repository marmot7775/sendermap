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
    SUBDOMAIN_MAILBOX = "in use for a subdomain's mail (MX)"
    SUBDOMAIN_MX = "receives replies and bounces for a sending subdomain (MX)"
    MTA_STS = "permitted MX host in the MTA-STS policy"
    SPF_INCLUDE = "included in SPF"
    SPF_NETWORK = "owns a network listed in SPF"
    DKIM_CNAME = "hosts a DKIM key (CNAME)"
    DKIM_NAME = "DKIM key named for it"
    RETURN_PATH = "bounce address CNAME"
    TRACKING = "link tracking CNAME"
    WEBSITE = "website loads a script or stylesheet from it"
    WEBSITE_MENTION = "mentioned on the website"
    SUBPROCESSOR = "named as a subprocessor"
    TOKEN = "verification token"
    AUTODISCOVER = "autodiscover CNAME"
    DKIM_REVOKED = "revoked DKIM key (empty p=)"
    DKIM_DANGLING = "DKIM CNAME to a missing key"
    CT_CNAME = "CNAME into its zone at a name from certificate logs"
    CT_ADDRESS = "address in its network at a name from certificate logs"
    DMARC_REPORTS = "receives DMARC reports"
    TLSRPT_REPORTS = "receives TLS reports"

    @property
    def tier(self) -> Tier | None:
        """The tier this kind of evidence supports; None for report addresses."""
        return _KIND_TIER.get(self)


_KIND_TIER = {
    Kind.MX: Tier.IN_USE,
    # In use for that subdomain only, so for the service as a whole it shows a configured setup.
    Kind.SUBDOMAIN_MAILBOX: Tier.CONFIGURED,
    # The policy lists hosts allowed to receive, in any mode; it does not show where mail goes.
    Kind.MTA_STS: Tier.CONFIGURED,
    Kind.SUBDOMAIN_MX: Tier.CONFIGURED,
    Kind.SPF_INCLUDE: Tier.CONFIGURED,
    Kind.SPF_NETWORK: Tier.CONFIGURED,
    Kind.DKIM_CNAME: Tier.CONFIGURED,
    Kind.RETURN_PATH: Tier.CONFIGURED,
    Kind.TRACKING: Tier.CONFIGURED,
    Kind.CT_CNAME: Tier.CONFIGURED,
    # A web host in a service's network: a landing page or app there, not mail set up.
    Kind.CT_ADDRESS: Tier.LIKELY,
    Kind.DKIM_NAME: Tier.LIKELY,
    Kind.WEBSITE: Tier.LIKELY,
    Kind.WEBSITE_MENTION: Tier.LIKELY,
    Kind.SUBPROCESSOR: Tier.LIKELY,
    Kind.TOKEN: Tier.ACCOUNT_ONLY,
    Kind.AUTODISCOVER: Tier.ACCOUNT_ONLY,
    Kind.DKIM_REVOKED: Tier.ACCOUNT_ONLY,
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
class CertificateEvidence(Evidence):
    """A name found in certificate transparency logs, the record it has now, and the validity of
    the latest certificate naming it. `name` is the hostname; `target` is the CNAME hop that
    matched a service, if a CNAME did."""

    not_before: str
    not_after: str
    target: str | None = None


@dataclass(frozen=True, slots=True)
class Claim:
    """What one piece of evidence shows about one service, at one name in the domain."""

    service: str
    kind: Kind
    where: str
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class Service:
    """One row of the map. A reporting service, known only from report addresses, has no tier:
    nothing shows that it sends."""

    name: str
    category: str
    tier: Tier | None
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
class Historical:
    """A name in certificate logs that no longer resolves, whose leftover CNAME points at a
    service: possibly a past vendor, never a current sender."""

    service: str
    evidence: CertificateEvidence


class CtStatus(StrEnum):
    OFF = "off"
    READ = "read from crt.sh"
    CACHED = "read from the local crt.sh cache"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class CtSummary:
    """How the certificate transparency source went: whether crt.sh answered, how many names it
    logged, how many were resolved, and how many no longer resolve and name no service."""

    status: CtStatus = CtStatus.OFF
    logged: int = 0
    resolved: int = 0
    gone_unnamed: int = 0


@dataclass(frozen=True, slots=True)
class Gap:
    """A question that got no usable answer: what was asked, and what happened instead. Its
    silence says nothing, so it is never to be read as absent."""

    asked: str
    happened: str


@dataclass(frozen=True, slots=True)
class Checked:
    """What was asked at one name: the DKIM selectors probed, the labels whose CNAMEs were
    asked, the pages requested. Silence about anything not listed here says nothing."""

    where: str
    dkim_selectors: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    pages: tuple[str, ...] = ()

    def __add__(self, other: Checked) -> Checked:
        """Both records of one name, each list in the order first asked, without repeats."""
        return Checked(
            self.where,
            tuple(dict.fromkeys(self.dkim_selectors + other.dkim_selectors)),
            tuple(dict.fromkeys(self.labels + other.labels)),
            tuple(dict.fromkeys(self.pages + other.pages)),
        )


@dataclass(frozen=True, slots=True)
class Observed:
    """What one source returns."""

    claims: tuple[Claim, ...] = ()
    unknowns: tuple[Unknown, ...] = ()
    findings: tuple[Finding, ...] = ()
    gaps: tuple[Gap, ...] = ()
    checked: tuple[Checked, ...] = ()
    historical: tuple[Historical, ...] = ()

    def __add__(self, other: Observed) -> Observed:
        return Observed(
            self.claims + other.claims,
            self.unknowns + other.unknowns,
            self.findings + other.findings,
            self.gaps + other.gaps,
            self.checked + other.checked,
            self.historical + other.historical,
        )

    def checked_by_name(self) -> tuple[Checked, ...]:
        """One Checked per name, in the order the names were first asked."""
        merged: dict[str, Checked] = {}
        for record in self.checked:
            merged[record.where] = (
                merged[record.where] + record if record.where in merged else record
            )
        return tuple(merged.values())


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
    checked: tuple[Checked, ...] = ()
    ct: CtSummary = field(default_factory=CtSummary)
    historical: tuple[Historical, ...] = ()
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
