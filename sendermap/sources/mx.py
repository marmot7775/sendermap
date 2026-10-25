"""MX: where the domain's mail is delivered. The strongest evidence there is.

An MX host no pattern names is looked up by address. When the networks that announce it are all
one service's own (vendors.json `networks`), the host is that service's, as a domain can name a
service's address under its own name: SendGrid's reverse DNS setup gives a dedicated address a
name such as o1.sendgrid.<domain>, and a domain whose MX points at it is credited to SendGrid.
"""

from __future__ import annotations

import asyncio
import ipaddress

from ..dns import Answer, Status
from ..model import (
    Claim,
    Evidence,
    Finding,
    Gap,
    GapKind,
    Kind,
    Observed,
    Outcome,
    Read,
    Severity,
    Unknown,
)
from . import Context, negative, networks

# The title of the finding a null MX at the domain raises (RFC 7505).
NULL_MX = "The domain accepts no mail"
# The title of the finding a domain that does not exist in DNS raises.
NO_DOMAIN = "The domain does not exist in DNS"


async def collect(ctx: Context, where: str) -> Observed:
    answer = await ctx.dns.query(where, "MX")
    if not answer.answered:
        gap = Gap(f"mail servers: MX at {where}", answer.status.value, GapKind.MX, 1)
        read = Read("mx", where, Outcome.FAILED, reason=f"{gap.asked}: {gap.happened}")
        return Observed(gaps=(gap,), reads=(read,))
    if not answer.ok:
        none = Read("mx", where, Outcome.NONE, (negative(answer, ctx.checked_at),))
        if where == ctx.domain and answer.status is Status.NXDOMAIN and not answer.chain:
            return Observed(findings=(_no_domain(ctx, answer),), reads=(none,))
        return Observed(reads=(none,))
    claims: list[Claim] = []
    unknowns: list[Unknown] = []
    findings: list[Finding] = []
    for record in answer.records:
        host = exchange(record)
        evidence = Evidence(where, "MX", record, ctx.checked_at)
        if not host:  # RFC 7505 null MX
            if where == ctx.domain:
                findings.append(
                    Finding(
                        Severity.NOTE,
                        NULL_MX,
                        "It publishes a null MX record, which tells senders it receives no email.",
                        (evidence,),
                    )
                )
            continue
        if service := ctx.catalog.mx(host):
            claims.append(Claim(service, kind_at(ctx, service, where), where, evidence))
        else:
            unknowns.append(Unknown("mail server", host, where, evidence))
    by_address = await asyncio.gather(*(_by_address(ctx, u) for u in unknowns))
    for unknown, claim in zip(unknowns.copy(), by_address, strict=True):
        if claim is None:
            continue
        unknowns.remove(unknown)
        claims.append(claim)
        if where == ctx.domain and ctx.catalog.category(claim.service) not in _RECEIVERS:
            findings.append(_sending_address(ctx, claim, unknown.value))
    found = tuple(Evidence(where, "MX", r, ctx.checked_at) for r in answer.records)
    read = Read("mx", where, Outcome.FOUND, found)
    return Observed(tuple(claims), tuple(unknowns), tuple(findings), reads=(read,))


# The categories whose hosts take in a domain's mail.
_RECEIVERS = ("Mailbox", "Security gateway")


async def _by_address(ctx: Context, unknown: Unknown) -> Claim | None:
    """The MX host credited to the service whose own networks announce its first address, with
    the address and the network answers as support; None when no one service's networks do, or
    a lookup fails. A shared cloud is never credited (networks.credited)."""
    address = await ctx.dns.query(unknown.value, "A")
    for ip in address.records if address.ok else ():
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        announced = await networks.owner(ctx, parsed)
        if announced and (service := networks.credited(ctx, announced)):
            found = Evidence(address.name, "A", ip, ctx.checked_at)
            support = (found, *announced.evidence)
            return Claim(service, Kind.MX_ADDRESS, unknown.where, unknown.evidence, support)
        return None
    return None


def _sending_address(ctx: Context, claim: Claim, host: str) -> Finding:
    """A domain's MX at an address of a service that sends but does not take in mail."""
    address = claim.supporting[0].value
    return Finding(
        Severity.WARNING,
        f"The MX at {ctx.domain} points at a {claim.service} sending address",
        f"{host} resolves to {address}, in {claim.service}'s own network. {claim.service} "
        "sends mail from its addresses; a name like this is usually set up for sending (reverse "
        "DNS), not to receive. Check that mail to the domain is delivered.",
        (claim.evidence, *claim.supporting),
    )


def _no_domain(ctx: Context, answer: Answer) -> Finding:
    return Finding(
        Severity.WARNING,
        NO_DOMAIN,
        f"DNS answers no such name for {ctx.domain}, so no mail can be sent or received as it. "
        "Check the spelling, or whether the registration has lapsed.",
        (negative(answer, ctx.checked_at),),
    )


def exchange(record: str) -> str:
    """The host an MX record points to, or "" for an RFC 7505 null MX."""
    host = record.partition(" ")[2]
    return "" if host == "." else host


def kind_at(ctx: Context, service: str, where: str) -> Kind:
    """At the domain, MX is where its mail is delivered. On a subdomain, a mailbox host or
    gateway is in use for that subdomain's mail only; a sending service's MX only takes in the
    replies and bounces to what it sends."""
    if where == ctx.domain:
        return Kind.MX
    mailbox = ctx.catalog.category(service) in ("Mailbox", "Security gateway")
    return Kind.SUBDOMAIN_MAILBOX if mailbox else Kind.SUBDOMAIN_MX
