"""Verification tokens: a TXT record a service asked the domain to publish to prove ownership.
A trace of an account, not evidence that the service sends."""

from __future__ import annotations

from ..model import Claim, Evidence, Kind, Observed
from . import Context


async def collect(ctx: Context) -> Observed:
    answer = await ctx.dns.txt(ctx.domain)
    claims = tuple(
        Claim(service, Kind.TOKEN, ctx.domain, Evidence(ctx.domain, "TXT", record))
        for record in answer.records
        if (service := ctx.catalog.token(record))
    )
    return Observed(claims)
