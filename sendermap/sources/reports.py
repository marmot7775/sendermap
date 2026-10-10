"""Report addresses: where the domain sends its DMARC and TLS reports. A service found only
here receives reports; it does not send the domain's mail."""

from __future__ import annotations

import asyncio

from ..model import Claim, Evidence, Kind, Observed, Unknown
from . import Context


def report_domains(record: str, tags: tuple[str, ...]) -> list[str]:
    """Domains of every mailto: address in the given tags, in order, without repeats."""
    found: list[str] = []
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if not sep or key.strip().lower() not in tags:
            continue
        for raw in value.split(","):
            uri = raw.strip()
            if not uri.lower().startswith("mailto:"):
                continue
            # RFC 6068: header fields after "?" are not the recipient; "!" starts a size limit.
            local, at, domain = uri[7:].split("?")[0].split("!")[0].strip().partition("@")
            domain = domain.lower().rstrip(".")
            if at and local and domain and "@" not in domain and domain not in found:
                found.append(domain)
    return found


async def collect(ctx: Context) -> Observed:
    dmarc, tlsrpt = await asyncio.gather(
        ctx.dns.txt(f"_dmarc.{ctx.domain}"), ctx.dns.txt(f"_smtp._tls.{ctx.domain}")
    )
    claims: list[Claim] = []
    unknowns: list[Unknown] = []
    for answer, prefix, tags, kind, label in (
        (dmarc, "v=dmarc1", ("rua", "ruf"), Kind.DMARC_REPORTS, "DMARC reports go to"),
        (tlsrpt, "v=tlsrptv1", ("rua",), Kind.TLSRPT_REPORTS, "TLS reports go to"),
    ):
        for record in (r for r in answer.records if r.lower().replace(" ", "").startswith(prefix)):
            for host in report_domains(record, tags):
                evidence = Evidence(answer.name, "TXT", record, ctx.checked_at)
                if service := ctx.catalog.reporting(host):
                    claims.append(Claim(service, kind, ctx.domain, evidence))
                elif not (host == ctx.domain or host.endswith("." + ctx.domain)):
                    unknowns.append(Unknown(label, host, ctx.domain))
    return Observed(tuple(claims), tuple(unknowns))
