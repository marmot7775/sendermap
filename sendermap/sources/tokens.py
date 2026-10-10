"""Verification tokens: a TXT record a service asked the domain to publish to prove ownership.
A trace of an account, not evidence that the service sends."""

from __future__ import annotations

from ..model import Claim, Evidence, Gap, Kind, Observed
from . import Context


async def collect(ctx: Context) -> Observed:
    answer = await ctx.dns.txt(ctx.domain)
    if not answer.answered:
        return Observed(
            gaps=(Gap(f"verification tokens: TXT at {ctx.domain}", answer.status.value),)
        )
    claims = tuple(
        Claim(service, Kind.TOKEN, ctx.domain, Evidence(ctx.domain, "TXT", record, ctx.checked_at))
        for record in answer.records
        if (service := ctx.catalog.token(record))
    )
    return Observed(claims)
