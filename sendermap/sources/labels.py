"""Bounce, tracking and autodiscover CNAMEs at the fixed labels services ask for.

A bounce (return path) CNAME lets a service's bounces align with the domain; a tracking CNAME
serves its click and open links. Either is the service set up to send. A wildcard CNAME answers
every label, so one random label is asked first and any answer matching it is ignored.
"""

from __future__ import annotations

import asyncio
import secrets

from ..model import Claim, Evidence, Kind, Observed
from . import Context

_KINDS = {
    "return path": Kind.RETURN_PATH,
    "tracking": Kind.TRACKING,
    "autodiscover": Kind.AUTODISCOVER,
}


async def collect(ctx: Context, where: str) -> Observed:
    labels = ctx.catalog.cname_labels
    canary, *answers = await asyncio.gather(
        ctx.dns.query(f"sm{secrets.token_hex(5)}.{where}", "CNAME"),
        *(ctx.dns.query(f"{label}.{where}", "CNAME") for label in labels),
    )
    wildcard = canary.target
    claims: list[Claim] = []
    for label, answer in zip(labels, answers, strict=True):
        target = answer.records[0] if answer.ok else answer.target
        if not target or target == wildcard:
            continue
        if match := ctx.catalog.label_cname(label, target):
            service, kind = match
            evidence = Evidence(f"{label}.{where}", "CNAME", target)
            claims.append(Claim(service, _KINDS[kind], where, evidence))
    return Observed(tuple(claims))
