"""Sending subdomains: where much of a brand's mail actually comes from.

Services ask for a subdomain of their own: email.example.com for Mailgun, bounce.example.com for
SparkPost, mail.example.com for Salesforce Marketing Cloud. A check of the main domain never sees
them. Candidates come from the labels services ask for and from certificate transparency logs;
a candidate counts as a sending subdomain when it publishes SPF or MX.
"""

from __future__ import annotations

import asyncio

import httpx

from ..dns import norm
from . import Context
from .spf import spf_records

CT_LOG = "https://api.certspotter.com/v1/issuances"
MAX_FROM_CT = 60


async def discover(ctx: Context) -> tuple[list[str], bool]:
    """Subdomains that publish SPF or MX, and whether certificate logs were read."""
    labels = {f"{label}.{ctx.domain}" for label in ctx.catalog.sending_labels}
    from_ct, ct_read = await _from_certificates(ctx)
    candidates = sorted(labels | from_ct)
    sending = await asyncio.gather(*(_sends(ctx, name) for name in candidates))
    return [name for name, yes in zip(candidates, sending, strict=True) if yes], ct_read


async def _sends(ctx: Context, name: str) -> bool:
    txt, mx = await asyncio.gather(ctx.dns.txt(name), ctx.dns.query(name, "MX"))
    return bool(spf_records(txt)) or mx.ok


async def _from_certificates(ctx: Context) -> tuple[set[str], bool]:
    if ctx.http is None:
        return set(), False
    try:
        response = await ctx.http.get(
            CT_LOG,
            params={"domain": ctx.domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=8,
        )
        response.raise_for_status()
        issuances = response.json()
    except (httpx.HTTPError, ValueError):
        return set(), False
    names: set[str] = set()
    for issuance in issuances:
        for raw in issuance.get("dns_names", []):
            name = norm(raw).removeprefix("*.")
            if name.endswith("." + ctx.domain) and name.count(".") <= ctx.domain.count(".") + 2:
                names.add(name)
    return set(sorted(names)[:MAX_FROM_CT]), True
