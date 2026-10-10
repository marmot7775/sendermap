"""Bounce, tracking and autodiscover CNAMEs at the fixed labels services ask for.

A bounce (return path) CNAME lets a service's bounces align with the domain; a tracking CNAME
serves its click and open links. Either is the service set up to send. A wildcard CNAME answers
every label, so one label nobody publishes is asked first and any answer matching it is ignored.
"""

from __future__ import annotations

import asyncio

from ..model import Checked, Claim, Evidence, Gap, Kind, Observed
from . import CANARY, Context

KINDS = {
    "return path": Kind.RETURN_PATH,
    "tracking": Kind.TRACKING,
    "autodiscover": Kind.AUTODISCOVER,
}


async def collect(ctx: Context, where: str) -> Observed:
    labels = ctx.catalog.cname_labels
    canary, *answers = await asyncio.gather(
        ctx.dns.query(f"{CANARY}.{where}", "CNAME"),
        *(ctx.dns.query(f"{label}.{where}", "CNAME") for label in labels),
    )
    wildcard = canary.target
    claims: list[Claim] = []
    failed: list[str] = []
    for label, answer in zip(labels, answers, strict=True):
        if not answer.answered:
            failed.append(label)
            continue
        target = answer.records[0] if answer.ok else answer.target
        if not target or target == wildcard:
            continue
        if match := ctx.catalog.label_cname(label, target):
            service, kind = match
            evidence = Evidence(f"{label}.{where}", "CNAME", target, ctx.checked_at)
            claims.append(Claim(service, KINDS[kind], where, evidence))
    gaps: list[Gap] = []
    if not canary.answered:
        gaps.append(
            Gap(
                f"wildcard check: CNAME at {CANARY}.{where}",
                f"{canary.status.value}, so a wildcard CNAME was not ruled out for the labels",
            )
        )
    if failed:
        names = ", ".join(f"{label}.{where}" for label in failed)
        gaps.append(Gap(f"bounce and tracking CNAMEs: CNAME at {names}", "lookup failed"))
    return Observed(tuple(claims), gaps=tuple(gaps), checked=(Checked(where, labels=labels),))
