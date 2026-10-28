"""The one view model every way of showing a SenderMap renders: findings first, each thing said
once, evidence rendered per kind, lists counted unless asked for.

`view` turns a map into a tree of frozen dataclasses that hold only words, counts and records as
text, so the terminal and Markdown views render the same View and hold no logic about the map.
It does no I/O and knows nothing of rich or Markdown.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC

from .. import story
from ..model import (
    CertificateEvidence,
    Checked,
    Claim,
    CtStatus,
    Finding,
    Gap,
    GapKind,
    Kind,
    Need,
    Reconciled,
    Reconciliation,
    SenderMap,
    Service,
    Setup,
    SetupItem,
    Severity,
    State,
    Tier,
    Unknown,
)
from ..setup import WORDS, words
from ..sources.dkim import SHORT_KEY_TITLE

__all__ = [
    "CLAIMED_PARTS",
    "NETWORK_VALUE",
    "RESOLVERS",
    "SECTIONS",
    "STATUS",
    "AbsenceView",
    "AskedView",
    "ClaimedPart",
    "FindingView",
    "GapGroup",
    "Head",
    "KindLine",
    "NetworkGroup",
    "OffView",
    "SenderMap",
    "ServiceView",
    "TierView",
    "UnknownView",
    "View",
    "asked",
    "asked_in_full",
    "claimed_parts",
    "ct_lines",
    "grouped_gaps",
    "grouped_unknowns",
    "listed",
    "resolver_words",
    "view",
]

# How sources/networks.py writes a range whose networks share one name: "<range> (<ASN>, <name>)"
# or "<range> (<ASN> and <ASN>, <name>)", with "; listed by <services>" before the closing
# bracket when services publish the range. A range whose networks have different names
# ("; <ASN>, <name>" again) does not match, so it stays a line of its own.
NETWORK_VALUE = r"^(\S+) \((AS\d+(?: and AS\d+)*), ((?:(?!; AS\d).)+?)(?:; listed by (.+))?\)$"
_NETWORK_VALUE = re.compile(NETWORK_VALUE)
_IP_KINDS = {"IP range in SPF": 0, "IP address in SPF": 1}
# The resolvers a run names, as a reader says them.
RESOLVERS = {
    "system": "the system resolver",
    "doh cloudflare": "Cloudflare DNS over HTTPS",
    "doh google": "Google DNS over HTTPS",
}
# The four parts of a reconciliation, in the words every view uses.
CLAIMED_PARTS = (
    ("confirmed", "Claimed and found"),
    ("unclaimed", "Found, not claimed"),
    ("unfound", "Claimed, not found at any name checked"),
    ("unknown", "Claimed, no service Sendermap knows by that name"),
)
_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}
_FIX = (Severity.RISK.value, Severity.WARNING.value)
# Each tier as a status a reader takes in at a glance. In use comes only from the domain's MX.
STATUS = {
    Tier.IN_USE.value: "Receives your mail",
    Tier.CONFIGURED.value: "Set up to send",
    Tier.LIKELY.value: "Likely sends",
    Tier.ACCOUNT_ONLY.value: "Account only",
}
# What each status means, for a reader who has not used Sendermap before.
STATUS_MEANS = {
    Tier.IN_USE.value: "your MX records deliver the domain's mail there",
    Tier.CONFIGURED.value: "its records for sending are in your DNS",
    Tier.LIKELY.value: "one clue points to it, such as a key named for it",
    Tier.ACCOUNT_ONLY.value: "an account exists, with nothing set up to send",
}

# The sections under a map's head, as (key, name), in the order every view shows them. The text,
# HTML and Markdown renderers each walk this tuple and take every name from it, so a section is
# renamed, added or moved here and nowhere else.
SECTIONS = (
    ("glance", "Who handles your email"),
    ("fixes", "What to fix"),
    ("notes", "Good to know"),
    ("evidence", "The proof, service by service"),
    ("claimed", "Your list against the map"),
    ("unknowns", "Not matched to a service"),
    ("ct", "Certificate logs"),
    ("absences", "Looked for and not found"),
    ("how", "How this was checked"),
)
# The plain sentence under each section's name, for a reader who does not know the records.
# The glance and evidence sections add lines of their own (View.intro).
INTROS = {
    "fixes": "Problems found in the setup, most serious first.",
    "notes": "Nothing to change here. These explain what the map shows.",
    "evidence": "The DNS records behind each service above, for anyone who wants to check them.",
    "claimed": "The services you said you use, compared with what DNS shows.",
    "unknowns": (
        "These records point somewhere Sendermap does not recognise: a service it does not know "
        "yet, or your own servers."
    ),
    "ct": "Names found in public certificate logs, checked against DNS today.",
    "absences": "Records Sendermap looked for and did not find.",
}
# The term a glossary line leads with, where it is not the label's first word.
_TERM = {
    "Bounce": "Bounce CNAME",
    "Tracking": "Tracking CNAME",
    "Verification": "Verification token",
    "Delegated": "Delegated by NS",
    "Website": "Website",
    "Subprocessor": "Subprocessor list",
    "CNAME": "From certificate logs",
    "Address": "From certificate logs",
    "Revoked": "Revoked DKIM key",
    "MTA-STS": "MTA-STS policy",
}
# What each kind of record does, in a few plain words, for the evidence section's key.
_MEANS = {
    "MX": "where the domain's mail is delivered",
    "MTA-STS": "names the servers allowed to receive the domain's mail, over encryption",
    "SPF": "the list of servers allowed to send as the domain",
    "DKIM": "a signature key that proves mail really came from the domain",
    "Bounce": "lets a service handle bounced mail under the domain's name",
    "Tracking": "links in a service's emails point here",
    "Verification": "proves the domain owner set up an account with the service",
    "Autodiscover": "lets mail apps find their settings",
    "Delegated": "the service runs DNS for a sending subdomain",
    "Website": "the domain's website uses or names the service",
    "Subprocessor": "the domain's own list of companies that handle its data",
    "CNAME from": "names found in public certificate logs",
    "Address from": "names found in public certificate logs",
    "Revoked": "a key the domain has deliberately emptied",
}

# ---------------------------------------------------------------- the View


@dataclass(frozen=True, slots=True)
class Head:
    """What was mapped, how, and the story written from the map."""

    domain: str
    senders: int
    lookups: int
    elapsed: float
    resolver: str
    checked_at: str
    story: str
    # The story's sentences, each a line of its own in the terminal view.
    sentences: tuple[str, ...] = ()

    @property
    def question(self) -> str:
        """The question the map answers: "Who handles email for glossier.com?"."""
        return f"Who handles email for {self.domain}?"

    def answer(self, fixes: int) -> str:
        """The answer in plain words: how many services handle the domain's email and how many
        things need fixing. "9 services handle email for glossier.com. 3 things need fixing."."""
        count = self.senders
        if not count:
            # The story says why nothing shows, so the answer would only repeat it.
            return "" if self.lede else f"No service shows up as handling email for {self.domain}."
        said = f"{count} service{'s' if count != 1 else ''} handle{'s' if count == 1 else ''}"
        said += f" email for {self.domain}."
        if fixes:
            return f"{said} {fixes} thing{'s need' if fixes != 1 else ' needs'} fixing."
        return f"{said} Nothing needs fixing."

    def made(self) -> str:
        """How the map was made in one sentence: "Checked <when>: 724 DNS lookups in 3.2 s over
        <resolver>."."""
        return (
            f"Checked {self.checked_at}: {self.lookups} DNS lookups in {self.elapsed:.1f} s "
            f"over {self.resolver}."
        )

    @property
    def lede(self) -> tuple[str, ...]:
        """The story's sentences without the last, what was not checked, which every view says
        in full under How this was checked. A story the rules did not write is one sentence."""
        said = self.sentences or ((self.story,) if self.story else ())
        return tuple(s for s in said if s and not s.startswith("Not checked"))


@dataclass(frozen=True, slots=True)
class FindingView:
    """One finding: its severity word, title and detail, and its records when evidence is set."""

    severity: str
    title: str
    detail: str
    records: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class KindLine:
    """The records of one kind under a service, counted and summarised in one line, with each
    record in full when evidence is set."""

    label: str
    summary: str
    records: tuple[str, ...] = ()

    def __str__(self) -> str:
        return f"{self.label}: {self.summary}"


@dataclass(frozen=True, slots=True)
class ServiceView:
    """One service: `where` is its one name when that is not the domain, `setup` its setup in
    one clause, empty when the vendor data describes none. `brief` is that clause as it reads
    without evidence, so a view that shows the records apart can still lead with it."""

    name: str
    category: str
    tier: str
    where: str
    kinds: tuple[KindLine, ...]
    setup: str
    brief: str = ""

    @property
    def status(self) -> str:
        """The tier as a plain status: "Receives your mail", "Set up to send", "Likely sends"."""
        return STATUS.get(self.tier, self.tier)

    @property
    def glance(self) -> tuple[str, str]:
        """(words, state) for a one-line overview: what a Likely or Account only tier rests on
        ("from: DKIM key", "basis"), else the setup in a few words, its state "complete",
        "incomplete" or "unchecked"; ("", "") when there is nothing to say."""
        if self.tier in (Tier.LIKELY.value, Tier.ACCOUNT_ONLY.value) and self.kinds:
            return f"from: {self.kinds[0].label}", "basis"
        said = self.brief.removeprefix("setup ")
        if said == "complete":
            return "setup complete", "complete"
        if said.startswith("incomplete"):
            return "setup incomplete", "incomplete"
        if said.startswith("not fully checked"):
            return "setup not fully checked", "unchecked"
        return "", ""


@dataclass(frozen=True, slots=True)
class TierView:
    tier: str
    services: tuple[ServiceView, ...]


@dataclass(frozen=True, slots=True)
class ClaimedPart:
    heading: str
    items: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnknownView:
    """One unrecognised sender, or one network's group of ranges and addresses (`grouped`): the
    records shown and how many more there are."""

    label: str
    values: tuple[str, ...]
    where: str
    grouped: bool
    records: tuple[str, ...]
    more: int = 0


@dataclass(frozen=True, slots=True)
class AbsenceView:
    asked: str
    happened: str
    answers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GapGroup:
    """The gaps of one kind, cap and outcome, said once: what was asked without the name, the
    names it applies to in map order, the outcome, the total count and the cap. `named` is
    false for a gap with no name of its own, which holds the domain as its one name."""

    asked: str
    names: tuple[str, ...]
    happened: str
    kind: GapKind
    count: int
    cap: int
    named: bool = True

    def places(self) -> tuple[str, ...]:
        """The names as a line shows them: those that share a parent lead with their own labels
        and the last carries the parent, as in "marketing", "receipts", "send.glossier.com"."""
        if len(self.names) < 2:
            return self.names
        parent = _shared_parent(self.names)
        if not parent:
            return self.names
        cut = len(parent) + 1
        return (*(n[:-cut] for n in self.names[:-1]), self.names[-1])

    def outcome(self) -> str:
        """What happened, with "at each" after its first sentence when it applies to several
        names: "82 of 109 not asked at each. The first 27 were asked, ..."."""
        if len(self.names) < 2:
            return self.happened
        first, stop, rest = self.happened.partition(". ")
        return f"{first} at each{stop}{rest}"

    def __str__(self) -> str:
        where = f" at {listed(self.places())}" if self.named else ""
        return f"{self.asked}{where}: {self.outcome()}"


@dataclass(frozen=True, slots=True)
class OffView:
    """A check that did not run because it is opt-in or was turned off: what it is, in a few
    words, and how to run it."""

    check: str
    how: str

    def __str__(self) -> str:
        """ "certificate transparency, crt.sh. Read only with --ct (...)."": the check, then how
        to run it as a sentence of its own."""
        return f"{self.check}. {self.how[:1].upper()}{self.how[1:]}."


@dataclass(frozen=True, slots=True)
class AskedView:
    """What was asked at one name, counted, and the names in full when evidence is set."""

    where: str
    counts: str
    names: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True, slots=True)
class View:
    """The sections of a map in the order every view shows them; an empty one is left out."""

    head: Head
    findings: tuple[FindingView, ...]
    tiers: tuple[TierView, ...]
    reporting: tuple[str, ...]
    claimed: tuple[ClaimedPart, ...]
    unknowns: tuple[UnknownView, ...]
    ct: tuple[str, ...]
    absences: tuple[AbsenceView, ...]
    gaps: tuple[GapGroup, ...]
    asked: tuple[AskedView, ...]
    evidence: bool
    off: tuple[OffView, ...] = ()
    # What was asked in all, as one line: "739 lookups at 4 names".
    asked_total: str = ""

    @property
    def fixes(self) -> tuple[FindingView, ...]:
        """The risks and warnings, in order: what a reader should fix."""
        return tuple(f for f in self.findings if f.severity in _FIX)

    @property
    def notes(self) -> tuple[FindingView, ...]:
        return tuple(f for f in self.findings if f.severity not in _FIX)

    @property
    def services(self) -> tuple[ServiceView, ...]:
        """Every service, strongest tier first."""
        return tuple(s for tier in self.tiers for s in tier.services)

    def intro(self, key: str) -> tuple[str, ...]:
        """The plain lines under a section's name: what the section shows, and for the glance
        what each status present means, for the evidence what each kind of record present
        does."""
        if key == "glance":
            tiers = [t.tier for t in self.tiers]
            means = tuple(f"{STATUS[t]}: {STATUS_MEANS[t]}." for t in tiers if t in STATUS_MEANS)
            return (f"Each service below receives or sends email for {self.head.domain}.", *means)
        lines: tuple[str, ...] = (INTROS[key],) if key in INTROS else ()
        if key == "evidence":
            lines += self.glossary
        return lines

    @property
    def glossary(self) -> tuple[str, ...]:
        """One line per kind of record the services show, in order of first appearance:
        "DKIM: a signature key that proves mail really came from the domain."."""
        said: dict[str, str] = {}
        for service in self.services:
            for kind in service.kinds:
                for word, means in _MEANS.items():
                    if kind.label.startswith(word):
                        term = word.split()[0] if word in ("CNAME from", "Address from") else word
                        said.setdefault(means, f"{_TERM.get(term, term)}: {means}.")
                        break
        return tuple(said.values())


def view(result: SenderMap, *, evidence: bool) -> View:
    """The map as a View. With `evidence` set it also holds every record in full and every name
    asked."""
    domain = result.domain
    covered = _covered(result)
    tiers: dict[str, list[ServiceView]] = {}
    for service in result.senders:
        if service.tier:
            tiers.setdefault(service.tier.value, []).append(
                _service(service, domain, covered, evidence)
            )
    return View(
        head=_head(result),
        findings=tuple(
            _merged(_findings(_by_severity(result.findings), evidence, _key_owners(result)))
        ),
        tiers=tuple(TierView(tier, tuple(services)) for tier, services in tiers.items()),
        reporting=tuple(s.name for s in result.reporting),
        claimed=tuple(
            ClaimedPart(heading, tuple(items))
            for heading, items in claimed_parts(result.reconciliation)
        )
        if result.reconciliation
        else (),
        unknowns=tuple(_unknown(u, domain, evidence) for u in grouped_unknowns(result.unknowns)),
        ct=tuple(ct_lines(result)),
        absences=tuple(
            AbsenceView(a.asked, a.happened, tuple(map(str, a.evidence))) for a in result.absences
        ),
        gaps=tuple(grouped_gaps(result.gaps, domain)),
        asked=tuple(
            AskedView(c.where, asked(c), tuple(asked_in_full(c)) if evidence else ())
            for c in result.checked
        ),
        evidence=evidence,
        off=tuple(_off(g) for g in result.gaps if g.kind is GapKind.OFF),
        asked_total=_asked_total(result),
    )


def _off(gap: Gap) -> OffView:
    """An opt-in or turned-off check in a few words: the check without the request it would
    make, and the reason as the source wrote it."""
    check = gap.asked.split(": GET ", 1)[0]
    how = gap.happened.removeprefix("not asked: ").removeprefix("not read: ")
    return OffView(check, how)


def _head(result: SenderMap) -> Head:
    run = result.run
    return Head(
        result.domain,
        len(result.senders),
        run.lookups,
        run.elapsed,
        resolver_words(run.resolver),
        run.checked_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        result.story,
        _sentences(result),
    )


def _sentences(result: SenderMap) -> tuple[str, ...]:
    """The story's sentences, or the story whole when it is not the one the rules write."""
    said = story.sentences(result)
    return tuple(said) if " ".join(said) == result.story else (result.story,)


def _by_severity(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_RANK[f.severity])


def _finding(finding: Finding, evidence: bool) -> FindingView:
    records = tuple(map(str, finding.evidence)) if evidence else ()
    return FindingView(finding.severity.value, finding.title, finding.detail, records)


def _key_owners(result: SenderMap) -> dict[str, str]:
    """{the name a DKIM key sits at: the service it is credited to}."""
    return {
        c.evidence.name: s.name for s in result.services for c in s.claims if c.kind in _KEY_KINDS
    }


def _owned(selector: str, where: str, owners: dict[str, str]) -> str:
    """The selector with the service its key belongs to: "s2 (SendGrid)", or the selector alone
    when no service is credited with it."""
    owner = owners.get(f"{selector}._domainkey.{where}")
    return f"{selector} ({owner})" if owner else selector


def _findings(
    findings: list[Finding], evidence: bool, owners: dict[str, str] | None = None
) -> list[FindingView]:
    """Each finding in order, with the short-key findings at one name and of one size said once,
    where the first of them stood: "Three DKIM keys at goop.com are 1024-bit: s1, s2 and k1",
    each key followed by the service it belongs to when one is credited with it."""
    owners = owners or {}
    groups: dict[tuple[str, str, str], list[tuple[str, Finding]]] = {}
    order: list[Finding | tuple[str, str, str]] = []
    for f in findings:
        match = SHORT_KEY_TITLE.match(f.title)
        if match is None:
            order.append(f)
            continue
        selector, where, bits = match.groups()
        key = (where, bits, f.detail)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((selector, f))
    shown: list[FindingView] = []
    for item in order:
        if isinstance(item, Finding):
            shown.append(_finding(item, evidence))
            continue
        members = groups[item]
        where, bits, detail = item
        if len(members) == 1:
            selector, only = members[0]
            owner = owners.get(f"{selector}._domainkey.{where}")
            single = _finding(only, evidence)
            if owner:
                title = f"The {owner} key {selector} at {where} is {bits}-bit"
                single = FindingView(single.severity, title, single.detail, single.records)
            shown.append(single)
            continue
        names = [s for s, _ in members]
        found = {owners.get(f"{s}._domainkey.{where}") for s in names}
        if len(found) == 1 and (owner := found.pop()):
            each = "both" if len(names) == 2 else "all"
            selectors = f"{listed(names)} ({each} {owner})"
        else:
            selectors = listed(_owned(s, where, owners) for s in names)
        title = f"{_count_words(len(members))} DKIM keys at {where} are {bits}-bit: {selectors}"
        records = tuple(str(e) for _, f in members for e in f.evidence) if evidence else ()
        shown.append(FindingView(members[0][1].severity.value, title, detail, records))
    return shown


# A finding's title that holds one name, as in "SPF at glossier.com is managed through Valimail".
_TITLE_NAME = re.compile(r"^(.*? at )([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)( .*)?$")


def _merged(findings: list[FindingView]) -> list[FindingView]:
    """Findings of one severity and detail whose titles differ only in the name they are at, said
    once where the first stood: "SPF at glossier.com and receipts.glossier.com is managed
    through Valimail"."""
    groups: dict[tuple[str, str, str, str], list[tuple[str, FindingView]]] = {}
    order: list[FindingView | tuple[str, str, str, str]] = []
    for f in findings:
        match = _TITLE_NAME.match(f.title)
        if match is None:
            order.append(f)
            continue
        before, name, after = match.groups()
        key = (f.severity, f.detail, before, after or "")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((name, f))
    shown: list[FindingView] = []
    for item in order:
        if isinstance(item, FindingView):
            shown.append(item)
            continue
        members = groups[item]
        severity, detail, before, after = item
        names = listed(dict.fromkeys(name for name, _ in members))
        records = tuple(r for _, f in members for r in f.records)
        title = members[0][1].title if len(members) == 1 else f"{before}{names}{after}"
        shown.append(FindingView(severity, title, detail, records))
    return shown


_NUMBERS = ("Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten")


def _count_words(n: int) -> str:
    return _NUMBERS[n] if n < len(_NUMBERS) else str(n)


# ---------------------------------------------------------------- services


def _service(
    service: Service, domain: str, covered: set[tuple[str, str, str]], evidence: bool
) -> ServiceView:
    names = {c.where for c in service.claims}
    where = next(iter(names)) if len(names) == 1 and domain not in names else ""
    base = where or domain
    return ServiceView(
        service.name,
        service.category,
        service.tier.value if service.tier else "",
        where,
        tuple(_kind_lines(service, base, evidence)),
        _setup_clause(service, base, covered, evidence),
        _setup_clause(service, base, covered, evidence=False),
    )


# How each kind reads as a line label, for one record and for several.
_LABELS: dict[Kind, tuple[str, str]] = {
    Kind.MX: ("MX", "MX"),
    Kind.SUBDOMAIN_MAILBOX: ("MX for a subdomain's mail", "MX for a subdomain's mail"),
    Kind.SUBDOMAIN_MX: ("MX for bounces", "MX for bounces"),
    Kind.MTA_STS: ("MTA-STS policy", "MTA-STS policy"),
    Kind.SPF_INCLUDE: ("SPF", "SPF"),
    Kind.SPF_NETWORK: ("SPF range", "SPF ranges"),
    Kind.SPF_EVALUATED: ("SPF passes its address", "SPF passes its addresses"),
    Kind.DKIM_CNAME: ("DKIM key", "DKIM keys"),
    Kind.DKIM_NAME: ("DKIM key", "DKIM keys"),
    Kind.DKIM_REVOKED: ("Revoked DKIM key", "Revoked DKIM keys"),
    Kind.DKIM_DANGLING: ("DKIM CNAME to a missing key", "DKIM CNAMEs to missing keys"),
    Kind.RETURN_PATH: ("Bounce CNAME", "Bounce CNAMEs"),
    Kind.DELEGATION: ("Delegated by NS", "Delegated by NS"),
    Kind.TRACKING: ("Tracking CNAME", "Tracking CNAMEs"),
    Kind.WEBSITE: ("Website loads", "Website loads"),
    Kind.WEBSITE_MENTION: ("Website mentions", "Website mentions"),
    Kind.SUBPROCESSOR: ("Subprocessor list", "Subprocessor list"),
    Kind.TOKEN: ("Verification token", "Verification tokens"),
    Kind.AUTODISCOVER: ("Autodiscover CNAME", "Autodiscover CNAMEs"),
    Kind.CT_CNAME: ("CNAME from certificate logs", "CNAMEs from certificate logs"),
    Kind.CT_ADDRESS: ("Address from certificate logs", "Addresses from certificate logs"),
    Kind.MX_ADDRESS: ("MX host in its network", "MX hosts in its network"),
    Kind.DMARC_REPORTS: ("DMARC reports", "DMARC reports"),
    Kind.TLSRPT_REPORTS: ("TLS reports", "TLS reports"),
}
_MX_KINDS = frozenset({Kind.MX, Kind.SUBDOMAIN_MAILBOX, Kind.SUBDOMAIN_MX, Kind.MX_ADDRESS})
_KEY_KINDS = frozenset({Kind.DKIM_CNAME, Kind.DKIM_NAME, Kind.DKIM_REVOKED, Kind.DKIM_DANGLING})
# Kinds whose record is told by the name it sits at, not by its value.
_NAMED_KINDS = frozenset(
    {
        Kind.RETURN_PATH,
        Kind.TRACKING,
        Kind.AUTODISCOVER,
        Kind.DELEGATION,
        Kind.CT_CNAME,
        Kind.CT_ADDRESS,
        Kind.DMARC_REPORTS,
        Kind.TLSRPT_REPORTS,
    }
)
_HOW = {Kind.DKIM_CNAME: "by CNAME", Kind.DKIM_NAME: "named for it"}
_BITS = re.compile(r"(\d+)-bit")
_SHOWN = 3  # items a kind line names before it counts the rest


def _kind_lines(service: Service, base: str, evidence: bool) -> list[KindLine]:
    """One line per kind, strongest kind first, the deciding claim first within its kind."""
    deciding = service.decided_by
    by_kind: dict[Kind, list[Claim]] = {}
    for claim in sorted(service.claims, key=lambda c: c is not deciding):
        by_kind.setdefault(claim.kind, []).append(claim)
    kinds = sorted(by_kind, key=lambda k: _strength(k, deciding.kind))
    return [_kind_line(kind, by_kind[kind], base, evidence) for kind in kinds]


def _strength(kind: Kind, deciding: Kind) -> tuple[int, int]:
    rank = kind.tier.rank if kind.tier else len(Tier)
    return (kind is not deciding, rank)


def _kind_line(kind: Kind, claims: list[Claim], base: str, evidence: bool) -> KindLine:
    items = list(dict.fromkeys(map(_item, claims)))
    sizes = _sizes(claims) if kind in _HOW else {}
    mixed = len(set(sizes.values())) > 1
    if mixed:
        items = [f"{item} {sizes[item]} bit" if item in sizes else item for item in items]
    one, several = _LABELS[kind]
    summary = ", ".join(items[:_SHOWN])
    if len(items) > _SHOWN:
        summary = f"{', '.join(items[: _SHOWN - 1])} and {len(items) - _SHOWN + 1} more"
    bits = _bits(claims) if kind in _HOW and not mixed else ""
    notes = [n for n in (bits, _HOW.get(kind, "")) if n]
    if notes:
        summary += f" ({', '.join(notes)})"
    names = list(dict.fromkeys(c.where for c in claims))
    if names != [base]:
        summary += f" at {listed(names)}"
    records = tuple(_record(c) for c in claims) if evidence else ()
    shown = one if len({c.evidence for c in claims}) == 1 else several
    return KindLine(shown, summary, records)


def _item(claim: Claim) -> str:
    """What one claim shows, in the fewest words: an MX host, a DKIM selector, the name a CNAME
    or report address sits at, or the record's value."""
    found = claim.evidence
    if claim.kind in _MX_KINDS:
        # A certificate log's value is "MX 10 host; named in a certificate valid ...".
        record = found.value.split(";", 1)[0].split()
        return record[-1] if record else found.value
    if claim.kind in _KEY_KINDS:
        return found.name.split("._domainkey.", 1)[0]
    if claim.kind in _NAMED_KINDS:
        return found.name
    return found.value


def _sizes(claims: list[Claim]) -> dict[str, int]:
    """{selector: its key size} for each key whose record says its size."""
    return {_item(c): int(m.group(1)) for c in claims if (m := _BITS.search(c.evidence.value))}


def _bits(claims: list[Claim]) -> str:
    """'2048 bit', 'both 2048 bit', 'all 1024 bit' or '1024 and 2048 bit'; empty when no key
    says."""
    sizes = [int(m.group(1)) for c in claims if (m := _BITS.search(c.evidence.value))]
    distinct = sorted(set(sizes))
    if not distinct:
        return ""
    if len(distinct) > 1:
        return f"{listed([str(n) for n in distinct])} bit"
    prefix = {1: "", 2: "both "}.get(len(sizes), "all ")
    return f"{prefix}{distinct[0]} bit"


def _record(claim: Claim) -> str:
    return str(claim.evidence) + "".join(f" via {e}" for e in claim.supporting)


# ---------------------------------------------------------------- setups


def _covered(result: SenderMap) -> set[tuple[str, str, str]]:
    """(service, name, record) of every setup item a finding already names: a missing or broken
    item whose records the finding holds, in a finding that names the service."""
    covered: set[tuple[str, str, str]] = set()
    for service in result.services:
        for setup in service.setups:
            for item in setup.items:
                if item.state in (State.MISSING, State.BROKEN) and any(
                    service.name in f.title and set(item.evidence) & set(f.evidence)
                    for f in result.findings
                ):
                    covered.add((service.name, setup.where, item.record))
    return covered


def _setup_clause(
    service: Service, base: str, covered: set[tuple[str, str, str]], evidence: bool
) -> str:
    """The service's setups in one clause. Complete when every required item is present at
    every name; otherwise the items that are missing, broken or not checked, with what was asked,
    and an item a finding names by its state alone. With `evidence` set, every item."""
    if not service.setups:
        return ""
    complete = [s.complete for s in service.setups]
    if all(complete):
        head = "setup complete"
    elif False in complete:
        head = "setup incomplete"
    else:
        head = "setup not fully checked"
    said: dict[str, list[str]] = {}
    for setup in service.setups:
        for item in setup.items:
            if evidence or _says(item):
                text = _item_words(service.name, setup, item, covered)
                said.setdefault(text, []).append(setup.where)
    if not said:
        return head
    one_name = {s.where for s in service.setups} == {base}
    parts = [text if one_name else f"{text} at {listed(names)}" for text, names in said.items()]
    return f"{head}: {', '.join(parts)}"


def _says(item: SetupItem) -> bool:
    """A required item that is not present is said without evidence; nothing else is."""
    return item.need is Need.REQUIRED and item.state is not State.PRESENT


def _item_words(
    name: str, setup: Setup, item: SetupItem, covered: set[tuple[str, str, str]]
) -> str:
    if (name, setup.where, item.record) in covered:
        return f"{WORDS[item.record]} {item.state.value}"
    return words(item)


# ---------------------------------------------------------------- not recognised


def resolver_words(name: str) -> str:
    """'the system resolver', 'Google DNS over HTTPS', 'DNS over HTTPS at <host>', or the name
    as the run gives it."""
    if name in RESOLVERS:
        return RESOLVERS[name]
    if name.startswith("doh "):
        return f"DNS over HTTPS at {name[4:]}"
    return name


@dataclass(frozen=True, slots=True)
class NetworkGroup:
    """The unrecognised IP ranges and addresses at one name that one network announces, under one
    owner name and one list of publishers. Each Unknown is kept whole, with its evidence."""

    asn: str
    name: str
    listed: str
    where: str
    members: tuple[tuple[str, Unknown], ...]  # (the range or address, the Unknown that shows it)

    def heading(self) -> str:
        """The group's line: "2 ranges and 1 address in AS16509 (Amazon Web Services)", with
        the services that publish them after a semicolon."""
        counts = [0, 0]
        for _, u in self.members:
            counts[_IP_KINDS[u.what]] += 1
        ranges, addresses = counts
        parts = [f"{ranges} range{'s' if ranges != 1 else ''}"] if ranges else []
        if addresses:
            parts.append(f"{addresses} address{'es' if addresses != 1 else ''}")
        by = f"; listed by {self.listed}" if self.listed else ""
        return f"{' and '.join(parts)} in {self.asn} ({self.name}){by}"


def grouped_unknowns(unknowns: tuple[Unknown, ...]) -> list[Unknown | NetworkGroup]:
    """The unknowns in their order, with the IP ranges and addresses that share a network, an
    owner name, a list of publishers and a name gathered into one group where the first of them
    stood. A range with no network, one alone in its network, and anything that is not an IP
    range stay as they are."""
    keyed: dict[tuple[str, str, str, str], list[tuple[str, Unknown]]] = {}
    order: list[Unknown | tuple[str, str, str, str]] = []
    for u in unknowns:
        match = _NETWORK_VALUE.match(u.value) if u.what in _IP_KINDS else None
        if match is None:
            order.append(u)
            continue
        cidr, asn, name, publishers = match.groups()
        key = (asn, name, publishers or "", u.where)
        if key not in keyed:
            keyed[key] = []
            order.append(key)
        keyed[key].append((cidr, u))
    out: list[Unknown | NetworkGroup] = []
    for item in order:
        if isinstance(item, Unknown):
            out.append(item)
        elif len(members := keyed[item]) == 1:
            out.append(members[0][1])
        else:
            out.append(NetworkGroup(*item, members=tuple(members)))
    return out


def _unknown(item: Unknown | NetworkGroup, domain: str, evidence: bool) -> UnknownView:
    """One unknown with its record, or one network's group with its first record, or every
    record when `evidence` is set."""
    where = "" if item.where == domain else item.where
    if isinstance(item, Unknown):
        return UnknownView(item.what, (item.value,), where, False, (str(item.evidence),))
    records = [str(u.evidence) for _, u in item.members]
    shown = records if evidence else records[:1]
    values = tuple(cidr for cidr, _ in item.members)
    return UnknownView(item.heading(), values, where, True, tuple(shown), len(records) - len(shown))


# ---------------------------------------------------------------- not checked

# A gap's question that ends at the name it was asked at: "DKIM selectors at send.glossier.com".
_AT_NAME = re.compile(r"^(.+) at ([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)$")


def grouped_gaps(gaps: Iterable[Gap], domain: str) -> list[GapGroup]:
    """The gaps that are not turned-off checks, one group per question, kind, cap and outcome,
    where the first of them stood, the names in map order and the counts added up. A gap whose
    question names no name of its own carries the domain."""
    groups: dict[tuple[str, str, GapKind, int, bool], list[tuple[str, Gap]]] = {}
    for gap in gaps:
        if gap.kind is GapKind.OFF:
            continue
        match = _AT_NAME.match(gap.asked)
        question, name = match.groups() if match else (gap.asked, domain)
        key = (question, gap.happened, gap.kind, gap.cap, match is not None)
        groups.setdefault(key, []).append((name, gap))
    return [
        GapGroup(
            question,
            tuple(dict.fromkeys(name for name, _ in members)),
            happened,
            kind,
            sum(g.count for _, g in members),
            cap,
            named,
        )
        for (question, happened, kind, cap, named), members in groups.items()
    ]


def _shared_parent(names: Iterable[str]) -> str:
    """The longest parent of two labels or more that every name sits under, or empty."""
    split = [n.split(".") for n in names]
    shared: list[str] = []
    for labels in zip(*(reversed(s) for s in split), strict=False):
        if len(set(labels)) != 1:
            break
        shared.insert(0, labels[0])
    while shared and any(len(s) <= len(shared) for s in split):
        shared.pop(0)
    return ".".join(shared) if len(shared) >= 2 else ""


# ---------------------------------------------------------------- claimed, CT, asked


def claimed_parts(reconciliation: Reconciliation) -> list[tuple[str, list[str]]]:
    """(heading, lines) for each of the four parts, every part shown, "none" when empty:
    "Microsoft 365, In use (claimed as "Office 365")", "Shopify, Configured", "Klaviyo", and
    an unknown name as the client wrote it."""
    parts: list[tuple[str, list[str]]] = []
    for key, heading in CLAIMED_PARTS:
        found: tuple[Reconciled | str, ...] = getattr(reconciliation, key)
        lines = [item if isinstance(item, str) else _reconciled(item, key) for item in found]
        parts.append((heading, lines or ["none"]))
    return parts


def _reconciled(item: Reconciled, part: str) -> str:
    line = item.service
    if part != "unfound":
        line += f", {item.tier}" if item.tier else ", receives reports only"
    if [item.service] != list(item.claimed_as) and item.claimed_as:
        line += f" (claimed as {', '.join(f'"{text}"' for text in item.claimed_as)})"
    return line


def _asked_total(result: SenderMap) -> str:
    if not result.checked:
        return ""
    lookups, names = result.run.lookups, len(result.checked)
    plural = ("s" if lookups != 1 else "", "s" if names != 1 else "")
    return f"{lookups} lookup{plural[0]} at {names} name{plural[1]}"


def asked(checked: Checked) -> str:
    """What was asked at one name, counted: "172 possible DKIM key names, 23 service record
    names, 2 web pages"."""
    counts = (
        (len(checked.dkim_selectors), "possible DKIM key name"),
        (len(checked.labels), "service record name"),
        (len(checked.pages), "web page"),
    )
    return ", ".join(f"{n} {what}{'s' if n != 1 else ''}" for n, what in counts if n) or "none"


def asked_in_full(checked: Checked) -> list[tuple[str, tuple[str, ...]]]:
    """(heading, names) for each list that has anything in it."""
    lists = (
        ("Pages", checked.pages),
        ("CNAME labels", checked.labels),
        ("DKIM selectors", checked.dkim_selectors),
    )
    return [(heading, names) for heading, names in lists if names]


def ct_lines(result: SenderMap) -> list[str]:
    """The certificate transparency section as plain lines; empty when CT was off."""
    if result.ct.status is CtStatus.OFF:
        return []
    summary = result.ct
    if summary.status is CtStatus.UNAVAILABLE:
        return ["No certificate log answered, so no names from certificate logs were checked."]
    said = "; ".join(
        f"{p.name} {p.status}, {p.logged} names"
        if p.status in (CtStatus.READ, CtStatus.CACHED)
        else f"{p.name} {p.status}"
        for p in summary.providers
    )
    lines = [f"{summary.logged} names logged ({said}); {summary.resolved} resolved now."]
    current = [
        (s.name, c)
        for s in result.services
        for c in s.claims
        if isinstance(c.evidence, CertificateEvidence)
    ]
    lines += [f"Current: {name} at {c.where} ({c.kind}): {c.evidence.value}" for name, c in current]
    if not current:
        lines.append("Current: no logged name points at a known service.")
    lines += [
        f"Possible past vendor: {h.service} at {h.evidence.name}: {h.evidence.value} "
        "(the name no longer resolves)"
        for h in result.historical
    ]
    if gone := summary.gone_unnamed:
        names = (
            "name no longer resolves and names" if gone == 1 else "names no longer resolve and name"
        )
        lines.append(f"{gone} other logged {names} no service.")
    return lines


def listed(items: Iterable[str]) -> str:
    """The items as prose: a; a and b; a, b and c."""
    names = list(items)
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"
