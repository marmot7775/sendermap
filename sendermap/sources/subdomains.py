"""Sending subdomains: where much of a brand's mail actually comes from.

Services ask for a subdomain of their own: email.example.com for Mailgun, bounce.example.com for
SparkPost, mail.example.com for Salesforce Marketing Cloud. A check of the main domain never sees
them. Candidates come from the labels services ask for and from certificate transparency logs;
a candidate counts as a sending subdomain when it publishes SPF or MX.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from ..dns import norm
from ..model import Gap
from . import Context, http_failure
from .spf import spf_records

CT_LOG = "https://api.certspotter.com/v1/issuances"
MAX_FROM_CT = 60
# Names deeper than this many labels below the domain are not asked.
MAX_CT_DEPTH = 2


@dataclass(frozen=True, slots=True)
class Found:
    """The candidates that publish SPF or MX, and every question that got no answer."""

    sending: tuple[str, ...] = ()
    gaps: tuple[Gap, ...] = ()


async def discover(ctx: Context) -> Found:
    labels = {f"{label}.{ctx.domain}" for label in ctx.catalog.sending_labels}
    from_ct, ct_gaps = await _from_certificates(ctx)
    candidates = sorted(labels | from_ct)
    answers = await asyncio.gather(*(_sends(ctx, name) for name in candidates))
    sending = tuple(name for name, sends in zip(candidates, answers, strict=True) if sends)
    failed = [name for name, sends in zip(candidates, answers, strict=True) if sends is None]
    gaps = ct_gaps
    if failed:
        asked = f"sending subdomains: TXT and MX at {', '.join(failed)}"
        gaps += (Gap(asked, "lookup failed, so whether they send is not known"),)
    return Found(sending, gaps)


async def _sends(ctx: Context, name: str) -> bool | None:
    """Whether `name` publishes SPF or MX; None when a lookup failed and neither was found."""
    txt, mx = await asyncio.gather(ctx.dns.txt(name), ctx.dns.query(name, "MX"))
    if spf_records(txt) or mx.ok:
        return True
    return False if txt.answered and mx.answered else None


async def _from_certificates(ctx: Context) -> tuple[set[str], tuple[Gap, ...]]:
    asked = f"certificate transparency log: GET {CT_LOG}?domain={ctx.domain}"
    if ctx.http is None:
        return set(), (Gap(asked, "not fetched: no web client"),)
    try:
        response = await ctx.http.get(
            CT_LOG,
            params={"domain": ctx.domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=8,
        )
        response.raise_for_status()
        issuances = response.json()
    except httpx.HTTPError as e:
        return set(), (Gap(asked, f"{http_failure(e)}, so only the common labels were asked"),)
    except ValueError:
        return set(), (Gap(asked, "the answer was not JSON, so only the common labels were asked"),)
    names: set[str] = set()
    deep: set[str] = set()
    for issuance in issuances:
        for raw in issuance.get("dns_names", []):
            name = norm(raw).removeprefix("*.")
            if not name.endswith("." + ctx.domain):
                continue
            too_deep = name.count(".") > ctx.domain.count(".") + MAX_CT_DEPTH
            (deep if too_deep else names).add(name)
    gaps: tuple[Gap, ...] = ()
    if deep:
        happened = f"{len(deep)} not asked (cap of {MAX_CT_DEPTH} labels below the domain)"
        gaps += (Gap(f"certificate log names more than {MAX_CT_DEPTH} labels deep", happened),)
    if len(names) > MAX_FROM_CT:
        happened = (
            f"{len(names) - MAX_FROM_CT} of {len(names)} not asked: only the first {MAX_FROM_CT} "
            "in alphabetical order were (cap)"
        )
        gaps += (Gap("certificate log names", happened),)
    return set(sorted(names)[:MAX_FROM_CT]), gaps
