"""Bounce, tracking and autodiscover CNAMEs at the fixed labels services ask for.

A bounce (return path) CNAME lets a service's bounces align with the domain; a tracking CNAME
serves its click and open links. Either is the service set up to send. A CNAME at one of these
labels into a zone outside the domain that no service's pattern matches is listed as unknown,
with its target. A wildcard CNAME answers every label, so one label nobody publishes is asked
first and any answer matching it is ignored.
"""

from __future__ import annotations

import asyncio

from ..dns import norm
from ..model import Checked, Claim, Evidence, Gap, Kind, Observed, Unknown
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
    unknowns: list[Unknown] = []
    failed: list[str] = []
    for label, answer in zip(labels, answers, strict=True):
        if not answer.answered:
            failed.append(label)
            continue
        target = answer.records[0] if answer.ok else answer.target
        if not target or target == wildcard:
            continue
        evidence = Evidence(f"{label}.{where}", "CNAME", target, ctx.checked_at)
        if match := ctx.catalog.label_cname(label, target):
            service, kind = match
            claims.append(Claim(service, KINDS[kind], where, evidence))
        elif not _inside(target, ctx.domain):
            unknowns.append(Unknown(f"CNAME at {label}", target, where, evidence))
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
    checked = (Checked(where, labels=labels),)
    return Observed(tuple(claims), tuple(unknowns), gaps=tuple(gaps), checked=checked)


def _inside(target: str, domain: str) -> bool:
    host = norm(target)
    return host == domain or host.endswith("." + domain)
