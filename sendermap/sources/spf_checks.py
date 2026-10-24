"""SPF by evaluation: asking a domain's record about each vendor's own sending address.

The walk in `spf.py` names the services a record names. Some records authorize services
without naming them: a hosted SPF service answers per address behind a macro, a flattened copy
lists ranges no service publishes as its own, a chain runs past the depth cap. At such a name,
this source runs `check_host` (`spf_eval.py`) once for each vendor with a sending address in the
vendor data that the walk did not already credit there, as a receiver would for mail from that
address, and keeps what each check decided.

A pass is a claim that the record authorizes one of the vendor's addresses; it says nothing about
the vendor's other addresses or whether the vendor sends. Any other result is kept for the
vendor's setup to read, and an error is a gap, except a permerror for passing the limit of two
lookups that find nothing: that is the record's own answer, which a receiver holding to the
limit gives too, so it is a finding about the record, once per name. The checks share a budget
of DNS lookups per map, counted through the map's lookups.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..model import Claim, Evidence, Finding, Gap, GapKind, Kind, Observed, Outcome, Read, Severity
from . import Context
from .spf import spf_records
from .spf_eval import TOO_MANY_VOIDS, VOID_LIMIT, Result, Verdict, check_host

BUDGET = 150  # DNS lookups per map, counted through the map's lookups
WAVE = 8  # checks run together; the budget is read between waves
# Every gap this source records starts with this, so the story can tell them from the walk's.
EVALUATION = "SPF evaluation"
# The kinds of claim that show the walk already credited a vendor at a name.
WALKED = frozenset({Kind.SPF_INCLUDE, Kind.SPF_NETWORK})
_ERRORS = frozenset({Result.PERMERROR, Result.TEMPERROR})
VOID_WORDS = {1: "one", 2: "two", 3: "three"}.get(VOID_LIMIT, str(VOID_LIMIT))


@dataclass(frozen=True, slots=True)
class Partial:
    """A name whose SPF record the walk could not read in full, and why."""

    where: str
    why: str


@dataclass(frozen=True, slots=True)
class _Ask:
    where: str
    vendor: str
    ip: str
    helo: str


async def collect(ctx: Context, needs: Sequence[Partial], claims: Iterable[Claim]) -> Observed:
    """Evaluate every name in `needs`, in order, for each vendor with a sending address, in the
    vendor data's order, that `claims` do not already credit there by SPF. Checks run eight at a
    time; once BUDGET lookups are spent, the rest are left and a gap at each name names them."""
    credited = {(c.where, c.service) for c in claims if c.kind in WALKED}
    asks = [
        _Ask(need.where, vendor, ip, ctx.catalog.sending_ip_host(vendor))
        for need in needs
        for vendor, ip in ctx.catalog.sending_ips.items()
        if (need.where, vendor) not in credited
    ]
    start = ctx.dns.count
    done: list[tuple[_Ask, Verdict]] = []
    while len(done) < len(asks) and ctx.dns.count - start < BUDGET:
        wave = asks[len(done) : len(done) + WAVE]
        verdicts = await asyncio.gather(
            *(check_host(ctx, a.ip, a.where, f"postmaster@{a.where}", a.helo) for a in wave)
        )
        done += zip(wave, verdicts, strict=True)
    observed = sum((_observed(ctx, ask, verdict) for ask, verdict in done), Observed())
    voids = await _too_many_voids(ctx, done)
    return observed + voids + _errors(done) + _left(asks[len(done) :])


def _observed(ctx: Context, ask: _Ask, verdict: Verdict) -> Observed:
    """A pass is a claim; fail, softfail, neutral or none is kept for the setup to read."""
    if verdict.result in _ERRORS:
        return Observed()
    assert verdict.record is not None  # every result but an error comes from a record
    decided = Evidence(
        verdict.record.name,
        "TXT",
        verdict.mechanism or verdict.record.value,
        ctx.checked_at,
    )
    if verdict.result is Result.PASS:
        claim = Claim(ask.vendor, Kind.SPF_EVALUATED, ask.where, decided, verdict.path)
        return Observed(claims=(claim,))
    at = verdict.mechanism or "the record's default"
    reason = f"{ask.ip}, one of {ask.vendor}'s addresses, gets {verdict.result} at {at}"
    read = Read("spf_eval", ask.where, Outcome.NONE, (decided, *verdict.path), ask.vendor, reason)
    return Observed(reads=(read,))


def _voided(verdict: Verdict) -> bool:
    return verdict.result is Result.PERMERROR and verdict.reason.startswith(TOO_MANY_VOIDS)


async def _too_many_voids(ctx: Context, done: Sequence[tuple[_Ask, Verdict]]) -> Observed:
    """One finding per name whose record ended in permerror for passing the void lookup limit,
    counting the services whose address it was asked about and quoting the first reason, and a
    read for each of them, as a fail leaves."""
    by_name: dict[str, list[tuple[_Ask, Verdict]]] = {}
    for ask, verdict in done:
        if _voided(verdict):
            by_name.setdefault(ask.where, []).append((ask, verdict))
    findings: list[Finding] = []
    reads: list[Read] = []
    for where, ended in by_name.items():
        records = spf_records(await ctx.dns.txt(where))
        evidence = tuple(Evidence(where, "TXT", r, ctx.checked_at) for r in records[:1])
        for ask, verdict in ended:  # kept for the vendor's setup to read, as a fail is
            reason = f"{ask.ip}, one of {ask.vendor}'s addresses, gets permerror: {verdict.reason}"
            reads.append(Read("spf_eval", where, Outcome.NONE, evidence, ask.vendor, reason))
        count = len(ended)
        services = f"{count} service{'' if count == 1 else 's'}"
        findings.append(
            Finding(
                Severity.NOTE,
                f"SPF at {where} ends in permerror for some senders before its default",
                f"Asked about one sending address each of {services}, the record ended in "
                f"permerror: {ended[0][1].reason}. RFC 7208 (section 4.6.4) allows "
                f"{VOID_WORDS} lookups that find nothing, and a receiver that holds to the limit "
                "stops there, so for these addresses it never reaches the record's later terms "
                "or its default, and SPF does not pass.",
                evidence,
            )
        )
    return Observed(findings=tuple(findings), reads=tuple(reads))


def _errors(done: Sequence[tuple[_Ask, Verdict]]) -> Observed:
    """One gap per name and reason, naming every vendor whose check ended in it."""
    by_reason: dict[tuple[str, str], list[str]] = {}
    for ask, verdict in done:
        if verdict.result in _ERRORS and not _voided(verdict):
            happened = f"{verdict.result}: {verdict.reason}"
            by_reason.setdefault((ask.where, happened), []).append(ask.vendor)
    gaps = tuple(
        Gap(
            f"{EVALUATION} at {where} for {', '.join(vendors)}", happened, GapKind.SPF, len(vendors)
        )
        for (where, happened), vendors in by_reason.items()
    )
    return Observed(gaps=gaps)


def _left(asks: Sequence[_Ask]) -> Observed:
    """One gap per name naming the vendors the budget left unevaluated there."""
    by_name: dict[str, list[str]] = {}
    for ask in asks:
        by_name.setdefault(ask.where, []).append(ask.vendor)
    gaps = tuple(
        Gap(
            f"{EVALUATION} at {where} for {', '.join(vendors)}",
            f"not evaluated. Evaluations ran until the budget of {BUDGET} lookups per map was "
            f"spent (cap {BUDGET} lookups).",
            GapKind.SPF,
            len(vendors),
            BUDGET,
        )
        for where, vendors in by_name.items()
    )
    return Observed(gaps=gaps)
