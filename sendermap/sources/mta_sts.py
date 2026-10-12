"""MTA-STS: a policy file in which the domain lists the hosts allowed to receive its mail.
It names the mailbox provider even when MX points at a gateway or an alias."""

from __future__ import annotations

import httpx

from ..model import Checked, Claim, Evidence, Gap, GapKind, Kind, Observed
from . import Context, http_failure
from .web import refusal


async def collect(ctx: Context) -> Observed:
    name = f"_mta-sts.{ctx.domain}"
    record = await ctx.dns.txt(name)
    if not record.answered:
        gap = Gap(f"MTA-STS: TXT at {name}", record.status.value, GapKind.MTA_STS)
        return Observed(gaps=(gap,))
    if not any(r.lower().startswith("v=stsv1") for r in record.records):
        return Observed()
    url = f"https://mta-sts.{ctx.domain}/.well-known/mta-sts.txt"
    if ctx.http is None:
        skipped = "not fetched: web and subdomain checks were both turned off"
        return Observed(gaps=(Gap(f"MTA-STS policy: GET {url}", skipped, GapKind.OFF),))
    if refused := await refusal(ctx.dns, url):
        gap = Gap(f"MTA-STS policy: GET {url}", f"not fetched: {refused}", GapKind.MTA_STS)
        return Observed(gaps=(gap,), checked=(Checked(ctx.domain, pages=(url,)),))
    try:
        response = await ctx.http.get(url, timeout=8)
        response.raise_for_status()
    except httpx.HTTPError as e:
        gap = Gap(f"MTA-STS policy: GET {url}", http_failure(e), GapKind.MTA_STS)
        return Observed(gaps=(gap,), checked=(Checked(ctx.domain, pages=(url,)),))
    claims = []
    for line in response.text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() != "mx":
            continue
        host = value.strip().removeprefix("*.")
        if service := ctx.catalog.mx(host):
            evidence = Evidence(url, "policy", line.strip(), ctx.checked_at)
            claims.append(Claim(service, Kind.MTA_STS, ctx.domain, evidence))
    return Observed(tuple(claims), checked=(Checked(ctx.domain, pages=(url,)),))
