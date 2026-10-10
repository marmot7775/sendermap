"""MX: where the domain's mail is delivered. The strongest evidence there is."""

from __future__ import annotations

from ..model import Claim, Evidence, Finding, Gap, Kind, Observed, Severity, Unknown
from . import Context


async def collect(ctx: Context, where: str) -> Observed:
    answer = await ctx.dns.query(where, "MX")
    if not answer.answered:
        return Observed(gaps=(Gap(f"MX at {where}", answer.status.value),))
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
            claims.append(Claim(service, _kind(ctx, service, where), where, evidence))
        else:
            unknowns.append(Unknown("mail server", host, where))
    return Observed(tuple(claims), tuple(unknowns), tuple(findings))


def exchange(record: str) -> str:
    """The host an MX record points to, or "" for an RFC 7505 null MX."""
    host = record.partition(" ")[2]
    return "" if host == "." else host


def _kind(ctx: Context, service: str, where: str) -> Kind:
    """A mailbox host is where mail lives, at the domain or a subdomain. A sending service's MX
    on a subdomain only takes in the replies and bounces to what it sends."""
    mailbox = ctx.catalog.category(service) in ("Mailbox", "Security gateway")
    return Kind.MX if where == ctx.domain or mailbox else Kind.SUBDOMAIN_MX
