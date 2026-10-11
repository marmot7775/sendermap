"""SPF: the servers and services a domain authorizes to send as it.

The record is a tree: includes point at other records, which include more. Walking it gives
three things: the services the domain itself authorizes, the raw IP ranges it lists (whose owners
the networks source looks up), and the lookup count receivers will spend on it.

Only authorizing terms count as evidence: a bare or "+" include, or a redirect, before "all".
Below a service's own record nothing more is credited; an ESP whose record includes Amazon SES
is that ESP, not an SES account of the domain.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime

from ..dns import Answer, norm
from ..model import (
    Claim,
    Evidence,
    Finding,
    Gap,
    Kind,
    Observed,
    Outcome,
    Read,
    Severity,
    Unknown,
)
from . import Context, negative

LOOKUP_LIMIT = 10  # RFC 7208 section 4.6.4
MAX_DEPTH = 10
_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})


@dataclass(frozen=True, slots=True)
class Term:
    qualifier: str
    mechanism: str
    value: str

    @property
    def authorizes(self) -> bool:
        return self.qualifier in ("", "+")

    @classmethod
    def parse(cls, text: str) -> Term:
        qualifier = text[0] if text[:1] in "+-~?" else ""
        body = text[len(qualifier) :]
        for sep in ("=", ":", "/"):
            head, found, tail = body.partition(sep)
            if found and head.isalnum():
                return cls(qualifier, head.lower(), tail if sep != "/" else "")
        return cls(qualifier, body.lower(), "")


def terms(record: str) -> list[Term]:
    return [Term.parse(t) for t in record.split()[1:]]


def spf_records(answer: Answer) -> list[str]:
    return [r for r in answer.records if r.lower() == "v=spf1" or r.lower().startswith("v=spf1 ")]


@dataclass(frozen=True, slots=True)
class SpfTree:
    """What the walk learned beyond claims: inputs for other sources and for findings."""

    record: str | None = None
    lookups: int = 0
    ranges: list[tuple[str, Evidence]] = field(default_factory=list)
    hosted_by: str | None = None
    # Flattening services whose record the walk read, so what it lists was credited.
    flattened: list[str] = field(default_factory=list)
    macros: list[str] = field(default_factory=list)
    # Include and redirect targets in the domain's record and one level below, lowercase.
    # A hint for ordering the DKIM scan, not evidence: qualifiers are not checked.
    includes: list[str] = field(default_factory=list)


async def collect(ctx: Context, where: str) -> tuple[Observed, SpfTree]:
    answer = await ctx.dns.txt(where)
    if not answer.answered:
        gap = Gap(f"SPF: TXT at {where}", answer.status.value)
        read = Read("spf", where, Outcome.FAILED, reason=f"{gap.asked}: {gap.happened}")
        return Observed(gaps=(gap,), reads=(read,)), SpfTree()
    records = spf_records(answer)
    if not records:
        none = (
            Evidence(where, "TXT", "no SPF record (v=spf1)", ctx.checked_at)
            if answer.ok
            else negative(answer, ctx.checked_at)
        )
        return Observed(reads=(Read("spf", where, Outcome.NONE, (none,)),)), SpfTree()
    if len(records) > 1:
        evidence = tuple(Evidence(where, "TXT", r, ctx.checked_at) for r in records)
        return Observed(
            reads=(Read("spf", where, Outcome.BROKEN, evidence),),
            findings=(
                Finding(
                    Severity.RISK,
                    f"{where} publishes {len(records)} SPF records",
                    "Receivers need exactly one. With more, SPF fails for every message (RFC 7208, "
                    "section 4.5), so no service listed in any of them is authorized.",
                    evidence,
                ),
            ),
        ), SpfTree()
    record = records[0]
    await _prefetch(ctx, record, depth=0, nearest={norm(where): 0})
    walked = await _Walk(ctx, where).visit(where, record, depth=0, inside=None, authorized=True)
    if too_deep := list(dict.fromkeys(walked.too_deep)):
        asked = f"SPF includes more than {MAX_DEPTH} levels below {where}: {', '.join(too_deep)}"
        happened = f"{len(too_deep)} not walked (cap of {MAX_DEPTH} levels)"
        walked += _Walked(observed=Observed(gaps=(Gap(asked, happened),)))
    tree = SpfTree(
        record=record,
        lookups=walked.lookups,
        ranges=list(walked.ranges),
        hosted_by=walked.hosted[0] if walked.hosted else None,
        flattened=list(walked.flattened),
        macros=list(walked.macros),
        includes=list(walked.includes),
    )
    return walked.observed + _findings(ctx, where, tree) + _read(ctx, where, tree), tree


def _read(ctx: Context, where: str, tree: SpfTree) -> Observed:
    """The record as a setup reads it: found, or unreadable when a hosted record the walk did not
    read or a macro can authorize services without naming them."""
    root = (Evidence(where, "TXT", tree.record or "", ctx.checked_at),)
    by = tree.hosted_by or ("a macro include" if tree.macros else None)
    if by and by not in tree.flattened:
        reason = f"managed through {by}, which can authorize services without naming them"
        return Observed(reads=(Read("spf", where, Outcome.UNREADABLE, root, reason=reason),))
    return Observed(reads=(Read("spf", where, Outcome.FOUND, root),))


def _evaluated(record: str) -> list[Term]:
    """The terms a receiver evaluates, in order: everything before "all", and a redirect only
    when the record has no "all"."""
    parsed = terms(record)
    has_all = any(t.mechanism == "all" for t in parsed)
    evaluated: list[Term] = []
    for term in parsed:
        if term.mechanism == "all":
            break
        if term.mechanism == "redirect" and has_all:
            continue
        evaluated.append(term)
    return evaluated


def _followable(term: Term) -> bool:
    return term.mechanism in ("include", "redirect") and bool(term.value)


async def _prefetch(ctx: Context, record: str, depth: int, nearest: dict[str, int]) -> None:
    """Ask for every record the walk can reach, all at once, so the walk can then read them in
    the order of their terms from the lookup cache without waiting on each in turn.

    `nearest` holds the shallowest depth each name was reached at, so the names asked depend
    only on the records, never on which answer came back first.
    """

    async def fetch(target: str) -> None:
        key = norm(target)
        if depth + 1 > MAX_DEPTH or nearest.get(key, MAX_DEPTH + 1) <= depth + 1:
            return
        nearest[key] = depth + 1
        records = spf_records(await ctx.dns.txt(target))
        if len(records) == 1:
            await _prefetch(ctx, records[0], depth + 1, nearest)

    targets = [t.value for t in _evaluated(record) if _followable(t) and "%{" not in t.value]
    await asyncio.gather(*map(fetch, targets))


@dataclass(frozen=True, slots=True)
class _Link:
    """One include or redirect in the tree, and what the walk knows on arriving at it."""

    parent: str  # the record that names the target
    target: str
    how: str  # "include" or "redirect"
    depth: int
    inside: str | None  # the service whose own record this is, if any
    live: bool  # every link from the domain down to here authorizes

    def evidence(self, checked_at: datetime) -> Evidence:
        sep = ":" if self.how == "include" else "="
        return Evidence(self.parent, "TXT", f"{self.how}{sep}{self.target}", checked_at)


@dataclass(frozen=True, slots=True)
class _Walked:
    """What one record and every record below it contributed, in the order of their terms."""

    observed: Observed = field(default_factory=Observed)
    lookups: int = 0
    ranges: tuple[tuple[str, Evidence], ...] = ()
    includes: tuple[str, ...] = ()
    macros: tuple[str, ...] = ()
    hosted: tuple[str, ...] = ()  # hosted SPF services on authorizing links
    too_deep: tuple[str, ...] = ()  # targets past MAX_DEPTH, not walked
    flattened: tuple[str, ...] = ()  # flattening services whose record was read

    def __add__(self, other: _Walked) -> _Walked:
        return _Walked(
            self.observed + other.observed,
            self.lookups + other.lookups,
            self.ranges + other.ranges,
            self.includes + other.includes,
            self.macros + other.macros,
            self.hosted + other.hosted,
            self.too_deep + other.too_deep,
            self.flattened + other.flattened,
        )


class _Walk:
    """Walks the tree one term at a time, depth first, so a name met twice is always walked at
    its first place in the record and every list comes out in the same order.

    A receiver evaluates a repeated include every time it meets it, so a repeat adds the lookups
    of everything below it again. Only the count is repeated: claims and ranges come from the
    first walk, and the records are read once, from the lookup cache.
    """

    def __init__(self, ctx: Context, where: str) -> None:
        self.ctx, self.where = ctx, where
        self.seen: set[str] = {norm(where)}
        self.lookups_below: dict[str, int] = {}  # per walked name, once its walk is done

    async def visit(
        self, name: str, record: str, depth: int, inside: str | None, authorized: bool
    ) -> _Walked:
        """Walk one record. `inside` is the service whose own record this is, if any;
        `authorized` is whether every link from the domain down to here authorizes."""
        walked = _Walked()
        for term in _evaluated(record):
            live = authorized and term.authorizes and inside is None
            walked += self._term(name, term, depth, live)
            if _followable(term):
                link = _Link(name, term.value, term.mechanism, depth, inside, live)
                walked += await self.follow(link)
        return walked

    def _term(self, name: str, term: Term, depth: int, live: bool) -> _Walked:
        """What one term says by itself: a lookup it costs, a range it lists, an include hint."""
        ranges: tuple[tuple[str, Evidence], ...] = ()
        if term.mechanism in ("ip4", "ip6") and live:
            evidence = Evidence(name, "TXT", f"{term.mechanism}:{term.value}", self.ctx.checked_at)
            ranges = ((term.value, evidence),)
        hint = _followable(term) and depth <= 1 and "%{" not in term.value
        return _Walked(
            lookups=int(term.mechanism in _LOOKUP_MECHANISMS),
            ranges=ranges,
            includes=(norm(term.value),) if hint else (),
        )

    async def follow(self, link: _Link) -> _Walked:
        if "%{" in link.target:
            service = self.ctx.catalog.spf(_macro_tail(link.target))
            hosted = (service,) if link.live and service else ()
            return _Walked(macros=(link.target,), hosted=hosted)
        service = self.ctx.catalog.spf(link.target)
        walked = self._credit(link, service) if link.live else _Walked()
        key = norm(link.target)
        if key in self.seen:
            if key not in self.lookups_below:  # still being walked: it includes itself
                return walked + _Walked(observed=Observed(findings=(self._loop(link),)))
            return walked + _Walked(lookups=self.lookups_below[key])
        if link.depth + 1 > MAX_DEPTH:
            return walked + _Walked(too_deep=(key,))
        self.seen.add(key)
        below = await self._below(link, service)
        self.lookups_below[key] = below.lookups
        return walked + below

    async def _below(self, link: _Link, service: str | None) -> _Walked:
        """Everything the target's own record contributes, walked for the first time."""
        answer = await self.ctx.dns.txt(link.target)
        if not answer.answered:
            gap = Gap(f"SPF {link.how}: TXT at {link.target}", answer.status.value)
            return _Walked(observed=Observed(gaps=(gap,)))
        records = spf_records(answer)
        if len(records) != 1:
            return _Walked()
        # A flattening service (EasyDMARC) copies the domain's own senders into its record,
        # so what is inside still speaks for the domain. Any other service's record is its own.
        flattened = service in self.ctx.catalog.flattening_spf
        owner = link.inside or (None if flattened else service)
        read = _Walked(flattened=(service,)) if flattened and service and link.live else _Walked()
        return read + await self.visit(link.target, records[0], link.depth + 1, owner, link.live)

    def _loop(self, link: _Link) -> Finding:
        return Finding(
            Severity.RISK,
            f"SPF at {self.where} includes {link.target} inside itself",
            f"{link.parent} names {link.target}, which is already being evaluated above it. A "
            f"receiver following it loops until it passes {LOOKUP_LIMIT} lookups and returns an "
            "error (RFC 7208, section 4.6.4), so SPF fails.",
            (link.evidence(self.ctx.checked_at),),
        )

    def _credit(self, link: _Link, service: str | None) -> _Walked:
        if service and self.ctx.catalog.is_hosted_spf(service):
            return _Walked(hosted=(service,))
        if service:
            claim = Claim(service, Kind.SPF_INCLUDE, self.where, link.evidence(self.ctx.checked_at))
            return _Walked(observed=Observed(claims=(claim,)))
        if not _is_own(link.target, self.ctx.domain):
            evidence = link.evidence(self.ctx.checked_at)
            unknown = Unknown("SPF include", link.target, self.where, evidence)
            return _Walked(observed=Observed(unknowns=(unknown,)))
        return _Walked()


def _findings(ctx: Context, where: str, tree: SpfTree) -> Observed:
    findings: list[Finding] = []
    root = Evidence(where, "TXT", tree.record or "", ctx.checked_at)
    if tree.lookups > LOOKUP_LIMIT:
        findings.append(
            Finding(
                Severity.RISK,
                f"SPF at {where} needs {tree.lookups} DNS lookups",
                f"Receivers stop at {LOOKUP_LIMIT} and return an error (RFC 7208, section "
                "4.6.4), so some or all mail fails SPF, depending on the order of the record.",
                (root,),
            )
        )
    if any(t.mechanism == "all" and t.qualifier == "+" for t in terms(tree.record or "")):
        findings.append(
            Finding(
                Severity.RISK,
                f"SPF at {where} authorizes every server",
                "It ends in +all, so any server on the internet passes SPF as this domain.",
                (root,),
            )
        )
    if tree.hosted_by or tree.macros:
        by = tree.hosted_by or "a macro include"
        if by in tree.flattened:
            detail = (
                f"{by} copies the domain's senders into its own record. The walk read that "
                "record, so the services and ranges it lists are reported here as the domain's."
            )
        elif by in ctx.catalog.flattening_spf:
            detail = (
                f"{by} copies the domain's senders into its own record, and the walk could not "
                "read it, so the services it lists are not reported here."
            )
        else:
            detail = (
                "A hosted or macro record can authorize services without naming them, so the "
                "services it covers do not show in the record itself."
            )
        findings.append(
            Finding(Severity.NOTE, f"SPF at {where} is managed through {by}", detail, (root,))
        )
    return Observed(findings=tuple(findings))


def _is_own(target: str, domain: str) -> bool:
    t = norm(target)
    return t == domain or t.endswith("." + domain)


def _macro_tail(target: str) -> str:
    """The fixed part after a macro: %{i}._ip.%{h}._spf.vali.email -> _spf.vali.email."""
    return target.rsplit("}", 1)[-1].lstrip(".")
