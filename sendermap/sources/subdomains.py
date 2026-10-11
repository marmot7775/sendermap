"""Sending subdomains: where much of a brand's mail actually comes from.

Services ask for a subdomain of their own: email.example.com for Mailgun, bounce.example.com for
SparkPost, mail.example.com for Salesforce Marketing Cloud. A check of the main domain never sees
them. Candidates come from the labels services ask for and from the names certificate logs hold
(read once per map by the CT source); a candidate counts as a sending subdomain when it
publishes SPF or MX, or is delegated by NS to a service's nameservers, as Klaviyo asks for
send.example.com: the service then publishes the subdomain's records itself, and the
delegation is its claim there. A delegation to nameservers no service is known by says nothing
about mail and is not asked about further.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass

from ..dns import Answer
from ..model import Claim, Evidence, Gap, Kind
from . import Context
from .spf import spf_records

MAX_FROM_CT = 60
# Names deeper than this many labels below the domain are not asked.
MAX_CT_DEPTH = 2


@dataclass(frozen=True, slots=True)
class Found:
    """The candidates that publish SPF or MX or are delegated to a service, the delegations,
    and every question that got no answer."""

    sending: tuple[str, ...] = ()
    gaps: tuple[Gap, ...] = ()
    delegations: tuple[Claim, ...] = ()


async def discover(ctx: Context, logged: Iterable[str]) -> Found:
    """Which candidates send: the common labels, and `logged`, the names certificate logs hold
    under the domain, within the caps."""
    labels = {f"{label}.{ctx.domain}" for label in ctx.catalog.sending_labels}
    from_ct, ct_gaps = _from_certificates(ctx, logged)
    candidates = sorted(labels | from_ct)
    answers = await asyncio.gather(*(_sends(ctx, name) for name in candidates))
    sending = tuple(name for name, (sends, _) in zip(candidates, answers, strict=True) if sends)
    failed = [name for name, (sends, _) in zip(candidates, answers, strict=True) if sends is None]
    gaps = ct_gaps
    if failed:
        asked = f"sending subdomains: TXT, MX and NS at {', '.join(failed)}"
        gaps += (Gap(asked, "lookup failed, so whether they send is not known"),)
    return Found(sending, gaps, tuple(c for _, claims in answers for c in claims))


async def _sends(ctx: Context, name: str) -> tuple[bool | None, tuple[Claim, ...]]:
    """Whether `name` publishes SPF or MX or is delegated to a service, and the delegation
    claims; None when a lookup failed and none of them was found."""
    txt, mx, ns = await asyncio.gather(
        ctx.dns.txt(name), ctx.dns.query(name, "MX"), ctx.dns.query(name, "NS")
    )
    delegations = delegated(ctx, ns)
    if spf_records(txt) or mx.ok or delegations:
        return True, delegations
    return (False if txt.answered and mx.answered and ns.answered else None), ()


def delegated(ctx: Context, ns: Answer) -> tuple[Claim, ...]:
    """A claim for each service whose nameservers the NS records at the name are, with the first
    of its records as evidence. NS records reached through a CNAME are the target's, not a
    delegation of the name, so they credit nobody."""
    if not ns.ok or ns.chain:
        return ()
    first: dict[str, str] = {}
    for host in ns.records:
        if service := ctx.catalog.delegation(host):
            first.setdefault(service, host)
    return tuple(
        Claim(service, Kind.DELEGATION, ns.name, Evidence(ns.name, "NS", host, ctx.checked_at))
        for service, host in first.items()
    )


def _from_certificates(ctx: Context, logged: Iterable[str]) -> tuple[set[str], tuple[Gap, ...]]:
    names: set[str] = set()
    deep: set[str] = set()
    for name in logged:
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
