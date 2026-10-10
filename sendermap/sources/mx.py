"""MX: where the domain's mail is delivered. The strongest evidence there is."""

from __future__ import annotations

from ..model import Claim, Evidence, Finding, Gap, Kind, Observed, Severity, Unknown
from . import Context


async def collect(ctx: Context, where: str) -> Observed:
    answer = await ctx.dns.query(where, "MX")
    if not answer.answered:
        return Observed(gaps=(Gap(f"mail servers: MX at {where}", answer.status.value),))
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
                        "The domain accepts no mail",
                        "It publishes a null MX record, which tells senders it receives no email.",
                        (evidence,),
                    )
                )
            continue
        if service := ctx.catalog.mx(host):
            claims.append(Claim(service, kind_at(ctx, service, where), where, evidence))
        else:
            unknowns.append(Unknown("mail server", host, where, evidence))
    return Observed(tuple(claims), tuple(unknowns), tuple(findings))


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
