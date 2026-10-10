"""Check every selector proof in data/vendors.json against live DNS.

For each proof, query the record and report found or not found, with what the
domain publishes there now. A record counts as found when it holds a DKIM key,
directly or through a CNAME; anything else at the name, such as a wildcard SPF
record, is not found. Exits 1 if any proof is not found.

Usage: python tools/verify_proofs.py
"""

from __future__ import annotations

import asyncio
import sys

from sendermap.dns import Answer, SystemResolver
from sendermap.selectors import Rule, load_rules
from sendermap.sources.dkim import Key


async def check(resolver: SystemResolver, rule: Rule) -> tuple[bool, str]:
    """(found, one line of report) for one rule's proof."""
    proof = rule.proof
    answer = await resolver.query(proof.record, "TXT")
    record = next((r for r in answer.records if "p=" in r), None)
    label = f"{rule.vendor} [{', '.join(rule.shape.expand())}] {proof.record} ({proof.date})"
    if record is None:
        return False, f"not found  {label}: {_published(answer)}"
    key = Key(proof.record.split(".", 1)[0], proof.record, record, answer.chain)
    return True, f"found      {label}: {key.evidence().value}"


def _published(answer: Answer) -> str:
    """What sits at the name when no DKIM key does."""
    via = f" via {' -> '.join(answer.chain)}" if answer.chain else ""
    if answer.records:
        return f"publishes {' | '.join(answer.records)}{via}"
    return f"{answer.status}{via}"


async def main() -> int:
    resolver = SystemResolver()
    results = await asyncio.gather(*(check(resolver, rule) for rule in load_rules()))
    for _, line in results:
        print(line)
    failed = sum(not found for found, _ in results)
    print(f"{len(results) - failed} of {len(results)} proofs found")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
