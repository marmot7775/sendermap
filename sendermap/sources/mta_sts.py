"""MTA-STS: a policy file in which the domain lists the hosts allowed to receive its mail.
It names the mailbox provider even when MX points at a gateway or an alias."""

from __future__ import annotations

import httpx

from ..model import Claim, Evidence, Kind, Observed
from . import Context


async def collect(ctx: Context) -> Observed:
    record = await ctx.dns.txt(f"_mta-sts.{ctx.domain}")
    if ctx.http is None or not any(r.lower().startswith("v=stsv1") for r in record.records):
        return Observed()
    url = f"https://mta-sts.{ctx.domain}/.well-known/mta-sts.txt"
    try:
        response = await ctx.http.get(url, timeout=8)
        response.raise_for_status()
    except httpx.HTTPError:
        return Observed()
    claims = []
    for line in response.text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() != "mx":
            continue
        host = value.strip().removeprefix("*.")
        if service := ctx.catalog.mx(host):
            evidence = Evidence(url, "policy", line.strip(), ctx.checked_at)
            claims.append(Claim(service, Kind.MTA_STS, ctx.domain, evidence))
    return Observed(tuple(claims))
