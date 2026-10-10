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

from ..dns import Answer
from ..model import Claim, Evidence, Finding, Gap, Kind, Observed, Severity, Unknown
from . import Context

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


@dataclass(slots=True)
class SpfTree:
    """What the walk learned beyond claims: inputs for other sources and for findings."""

    record: str | None = None
    lookups: int = 0
    ranges: list[tuple[str, Evidence]] = field(default_factory=list)
    hosted_by: str | None = None
    macros: list[str] = field(default_factory=list)
    # Include and redirect targets in the domain's record and one level below, lowercase.
    # A hint for ordering the DKIM scan, not evidence: qualifiers are not checked.
    includes: list[str] = field(default_factory=list)


async def collect(ctx: Context, where: str) -> tuple[Observed, SpfTree]:
    answer = await ctx.dns.txt(where)
    tree = SpfTree()
    if not answer.answered:
        return Observed(gaps=(Gap(f"SPF at {where}", answer.status.value),)), tree
    records = spf_records(answer)
    if not records:
        return Observed(), tree
    if len(records) > 1:
        evidence = tuple(Evidence(where, "TXT", r) for r in records)
        return Observed(
            findings=(
                Finding(
                    Severity.RISK,
                    f"{where} publishes {len(records)} SPF records",
                    "Receivers need exactly one. With more, SPF fails for every message (RFC 7208, "
                    "section 4.5), so no service listed in any of them is authorized.",
                    evidence,
                ),
            )
        ), tree
    tree.record = records[0]
    walk = _Walk(ctx, where, tree)
    await walk.visit(where, tree.record, depth=0, inside=None, authorized=True)
    return walk.observed(), tree


@dataclass(frozen=True, slots=True)
class _Link:
    """One include or redirect in the tree, and what the walk knows on arriving at it."""

    parent: str  # the record that names the target
    target: str
    how: str  # "include" or "redirect"
    depth: int
    inside: str | None  # the service whose own record this is, if any
    live: bool  # every link from the domain down to here authorizes

    @property
    def evidence(self) -> Evidence:
        sep = ":" if self.how == "include" else "="
        return Evidence(self.parent, "TXT", f"{self.how}{sep}{self.target}")


class _Walk:
    def __init__(self, ctx: Context, where: str, tree: SpfTree) -> None:
        self.ctx, self.where, self.tree = ctx, where, tree
        self.claims: list[Claim] = []
        self.unknowns: list[Unknown] = []
        self.gaps: list[Gap] = []
        self.seen: set[str] = {where}

    async def visit(
        self, name: str, record: str, depth: int, inside: str | None, authorized: bool
    ) -> None:
        """Walk one record. `inside` is the service whose own record this is, if any;
        `authorized` is whether every link from the domain down to here authorizes."""
        parsed = terms(record)
        has_all = any(t.mechanism == "all" for t in parsed)
        links: list[_Link] = []
        for term in parsed:
            if term.mechanism == "all":
                break  # nothing after "all" is ever evaluated
            if term.mechanism == "redirect" and has_all:
                continue  # a redirect is ignored when the record has "all"
            if term.mechanism in _LOOKUP_MECHANISMS:
                self.tree.lookups += 1
            live = authorized and term.authorizes and inside is None
            if term.mechanism in ("ip4", "ip6") and live:
                evidence = Evidence(name, "TXT", f"{term.mechanism}:{term.value}")
                self.tree.ranges.append((term.value, evidence))
            if term.mechanism in ("include", "redirect") and term.value:
                if depth <= 1 and "%{" not in term.value:
                    self.tree.includes.append(term.value.lower().rstrip("."))
                links.append(_Link(name, term.value, term.mechanism, depth, inside, live))
        await asyncio.gather(*map(self.follow, links))

    async def follow(self, link: _Link) -> None:
        if "%{" in link.target:
            self.tree.macros.append(link.target)
            if link.live and (service := self.ctx.catalog.spf(_macro_tail(link.target))):
                self.tree.hosted_by = self.tree.hosted_by or service
            return
        service = self.ctx.catalog.spf(link.target)
        if link.live:
            self._credit(link, service)
        key = link.target.lower().rstrip(".")
        if key in self.seen or link.depth + 1 > MAX_DEPTH:
            return
        self.seen.add(key)
        answer = await self.ctx.dns.txt(link.target)
        if not answer.answered:
            self.gaps.append(Gap(f"SPF at {link.target}", answer.status.value))
            return
        records = spf_records(answer)
        if len(records) == 1:
            # A flattening service (EasyDMARC) copies the domain's own senders into its record,
            # so what is inside still speaks for the domain. Any other service's record is its own.
            flattened = service in self.ctx.catalog.flattening_spf
            owner = link.inside or (None if flattened else service)
            await self.visit(link.target, records[0], link.depth + 1, owner, link.live)

    def _credit(self, link: _Link, service: str | None) -> None:
        if self.ctx.catalog.is_hosted_spf(service):
            self.tree.hosted_by = self.tree.hosted_by or service
        elif service:
            self.claims.append(Claim(service, Kind.SPF_INCLUDE, self.where, link.evidence))
        elif not _is_own(link.target, self.ctx.domain):
            self.unknowns.append(Unknown("SPF include", link.target, self.where))

    def observed(self) -> Observed:
        findings: list[Finding] = []
        tree, root = self.tree, Evidence(self.where, "TXT", self.tree.record or "")
        if tree.lookups > LOOKUP_LIMIT:
            findings.append(
                Finding(
                    Severity.RISK,
                    f"SPF at {self.where} needs {tree.lookups} DNS lookups",
                    f"Receivers stop at {LOOKUP_LIMIT} and return an error (RFC 7208, section "
                    "4.6.4), so some or all mail fails SPF, depending on the order of the record.",
                    (root,),
                )
            )
        if any(t.mechanism == "all" and t.qualifier == "+" for t in terms(tree.record or "")):
            findings.append(
                Finding(
                    Severity.RISK,
                    f"SPF at {self.where} authorizes every server",
                    "It ends in +all, so any server on the internet passes SPF as this domain.",
                    (root,),
                )
            )
        if tree.hosted_by or tree.macros:
            by = tree.hosted_by or "a macro include"
            findings.append(
                Finding(
                    Severity.NOTE,
                    f"SPF at {self.where} is managed through {by}",
                    "A hosted or macro record can authorize services without naming them, so the "
                    "services it covers do not show in the record itself.",
                    (root,),
                )
            )
        return Observed(tuple(self.claims), tuple(self.unknowns), tuple(findings), tuple(self.gaps))


def _is_own(target: str, domain: str) -> bool:
    t = target.lower().rstrip(".")
    return t == domain or t.endswith("." + domain)


def _macro_tail(target: str) -> str:
    """The fixed part after a macro: %{i}._ip.%{h}._spf.vali.email -> _spf.vali.email."""
    return target.rsplit("}", 1)[-1].lstrip(".")
