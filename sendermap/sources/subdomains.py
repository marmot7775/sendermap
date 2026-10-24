"""Sending subdomains: where much of a brand's mail actually comes from.

Services ask for a subdomain of their own: email.example.com for Mailgun, bounce.example.com for
SparkPost, mail.example.com for Salesforce Marketing Cloud. A check of the main domain never sees
them. Candidates come from the labels services ask for and from the names certificate logs hold
(read once per map by the CT source); a candidate counts as a sending subdomain when it
publishes SPF or MX, or is delegated by NS to a service's nameservers, as Klaviyo asks for
send.example.com: the service then publishes the subdomain's records itself, and the
delegation is its claim there. A delegation to nameservers no service is known by says nothing
about mail and is not asked about further.

A zone with a wildcard answers every name: shopify.com and gov.uk give the same SPF at any
label. So a name no one would publish is asked first, and a candidate whose SPF or MX is the
same as that name's is the wildcard answering, not a subdomain of its own.

A candidate that is an alias of the domain or of another candidate, as www.github.com is of
github.com, answers with that name's SPF and MX. Those are already mapped where they are
published, so the alias is not a sending subdomain: counting it would repeat each service at
it and report a DKIM key missing there that was never set up.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass

from ..dns import Answer
from ..model import Claim, Evidence, Gap, GapKind, Kind
from . import Context
from .spf import spf_records

MAX_FROM_CT = 60
# The label asked to see whether the zone answers every name, as the DKIM source asks one.
WILDCARD_CHECK = "sendermap-wildcard-check"
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
    wildcard, *found = await asyncio.gather(
        _asked(ctx, f"{WILDCARD_CHECK}.{ctx.domain}"), *(_asked(ctx, n) for n in candidates)
    )
    mapped = {ctx.domain, *candidates}
    answers = [
        (False, ()) if _alias_of(each, mapped) else _sends(ctx, each, wildcard) for each in found
    ]
    sending = tuple(
        name for name, (sends, _) in zip(candidates, answers, strict=True) if sends is True
    )
    gaps = ct_gaps
    for servfail, happened in _FAILED:
        failed = [n for n, (sends, _) in zip(candidates, answers, strict=True) if sends == servfail]
        if failed:
            asked = f"sending subdomains: TXT, MX and NS at {', '.join(failed)}"
            gaps += (Gap(asked, happened, GapKind.SUBDOMAINS, len(failed)),)
    return Found(sending, gaps, tuple(c for _, claims in answers for c in claims))


# How a candidate whose lookups failed reads, by who failed: the domain's own servers (SERVFAIL,
# often a subdomain delegated to nameservers that no longer serve it) or the lookup itself.
SERVFAIL, NO_ANSWER = "servfail", "no answer"
_FAILED = (
    (
        SERVFAIL,
        "the domain's DNS servers failed to answer (SERVFAIL), so whether they send is not known",
    ),
    (NO_ANSWER, "lookup failed, so whether they send is not known"),
)


Asked = tuple[Answer, Answer, Answer]  # TXT, MX and NS at one name


async def _asked(ctx: Context, name: str) -> Asked:
    txt, mx, ns = await asyncio.gather(
        ctx.dns.txt(name), ctx.dns.query(name, "MX"), ctx.dns.query(name, "NS")
    )
    return txt, mx, ns


def _alias_of(answers: Asked, mapped: set[str]) -> bool:
    """Whether the name's SPF or MX came through a CNAME to a name that is mapped anyway."""
    txt, mx, _ = answers
    return any(a.target in mapped for a in (txt, mx) if a.target)


def _sends(ctx: Context, answers: Asked, wildcard: Asked) -> tuple[bool | str, tuple[Claim, ...]]:
    """Whether a name publishes SPF or MX of its own, not the wildcard's, or is delegated to a
    service, and the delegation claims; SERVFAIL or NO_ANSWER when a lookup failed and none of
    them was found."""
    txt, mx, ns = answers
    spf = spf_records(txt)
    own_spf = bool(spf) and spf != spf_records(wildcard[0])
    own_mx = mx.ok and not (wildcard[1].ok and wildcard[1].records == mx.records)
    delegations = delegated(ctx, ns)
    if own_spf or own_mx or delegations:
        return True, delegations
    if spf or mx.ok:  # the wildcard's answer, so nothing of its own
        return False, ()
    failed = [a for a in (txt, mx, ns) if not a.answered]
    if not failed:
        return False, ()
    return (SERVFAIL if all(a.servfail for a in failed) else NO_ANSWER), ()


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
        happened = (
            f"{len(deep)} not asked. Names up to {MAX_CT_DEPTH} labels below the domain were "
            f"asked (cap {MAX_CT_DEPTH} labels)."
        )
        asked = f"certificate log names more than {MAX_CT_DEPTH} labels deep"
        gaps += (Gap(asked, happened, GapKind.CERTIFICATE_LOG, len(deep), MAX_CT_DEPTH),)
    if len(names) > MAX_FROM_CT:
        happened = (
            f"{len(names) - MAX_FROM_CT} of {len(names)} not asked. The first {MAX_FROM_CT} in "
            f"alphabetical order were asked (cap {MAX_FROM_CT})."
        )
        dropped = len(names) - MAX_FROM_CT
        gaps += (
            Gap("certificate log names", happened, GapKind.CERTIFICATE_LOG, dropped, MAX_FROM_CT),
        )
    return set(sorted(names)[:MAX_FROM_CT]), gaps
