"""Check every selector proof in data/vendors.json against live DNS.

For each proof, query the record once and report found, not found, or could not check, with what
the domain publishes there now. A record counts as found when it holds a DKIM key, directly or
through a CNAME; anything else at the name, such as a wildcard SPF record, is not found. A lookup
that times out or fails is could not check: it says nothing about the proof, so it is listed but
never fails the run. Exits 1 if any proof is not found.

Usage: python tools/verify_proofs.py [--json]

--json prints one JSON object per proof, one per line, with vendor, selector, domain, record,
expected, observed and status; the totals line goes to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict, dataclass

from sendermap.dns import Answer, Resolver, Status, SystemResolver
from sendermap.selectors import Proof, Rule, load_rules
from sendermap.sources.dkim import Key

FOUND = "found"
NOT_FOUND = "not found"
UNCHECKED = "could not check"

EXPECTED = "TXT record holding a DKIM key (p=)"
TIMEOUT = 3.0  # seconds per query
CONCURRENCY = 4


@dataclass(frozen=True, slots=True)
class Result:
    vendor: str
    selector: str
    domain: str
    record: str
    expected: str
    observed: str
    status: str


async def check(resolver: Resolver, rule: Rule, proof: Proof) -> tuple[Result, str]:
    """The result for one of a rule's proofs, and its line of text report."""
    answer = await resolver.query(proof.record, "TXT")
    record = next((r for r in answer.records if "p=" in r), None)
    label = f"{rule.vendor} [{', '.join(rule.shape.expand())}] {proof.record} ({proof.date})"
    if not answer.answered:
        status, line = UNCHECKED, f"unchecked  {label}: {answer.status}"
    elif record is None:
        status, line = NOT_FOUND, f"not found  {label}: {_published(answer)}"
    else:
        key = Key(proof.record.split(".", 1)[0], proof.record, record, answer.chain)
        status, line = FOUND, f"found      {label}: {key.evidence().value}"
    result = Result(
        vendor=rule.vendor,
        selector=proof.record.split(".", 1)[0],
        domain=proof.domain,
        record=proof.record,
        expected=EXPECTED,
        observed=_observed(answer),
        status=status,
    )
    return result, line


def _published(answer: Answer) -> str:
    """What sits at the name when no DKIM key does."""
    via = f" via {' -> '.join(answer.chain)}" if answer.chain else ""
    if answer.records:
        return f"publishes {' | '.join(answer.records)}{via}"
    return f"{answer.status}{via}"


def _observed(answer: Answer) -> str:
    """The raw answer: its records, or NXDOMAIN, no data, or the failure."""
    via = f" (via {' -> '.join(answer.chain)})" if answer.chain else ""
    match answer.status:
        case Status.OK:
            return " | ".join(answer.records) + via
        case Status.NXDOMAIN:
            return "NXDOMAIN" + via
        case Status.NOANSWER:
            return "no data" + via
        case _:
            return "lookup failed or timed out"


async def verify(resolver: Resolver, rules: tuple[Rule, ...]) -> list[tuple[Result, str]]:
    """Check every proof, a few at a time."""
    limit = asyncio.Semaphore(CONCURRENCY)

    async def one(rule: Rule, proof: Proof) -> tuple[Result, str]:
        async with limit:
            return await check(resolver, rule, proof)

    return await asyncio.gather(*(one(rule, proof) for rule in rules for proof in rule.proofs))


def totals(results: list[Result]) -> str:
    found = sum(r.status == FOUND for r in results)
    unchecked = sum(r.status == UNCHECKED for r in results)
    line = f"{found} of {len(results)} proofs found"
    return f"{line}, {unchecked} could not be checked" if unchecked else line


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check every selector proof against live DNS.")
    parser.add_argument("--json", action="store_true", help="print one JSON object per proof")
    args = parser.parse_args(argv)

    checked = await verify(SystemResolver(timeout=TIMEOUT), load_rules())
    results = [result for result, _ in checked]
    for result, line in checked:
        print(json.dumps(asdict(result)) if args.json else line)
    print(totals(results), file=sys.stderr if args.json else sys.stdout)
    return 1 if any(r.status == NOT_FOUND for r in results) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
