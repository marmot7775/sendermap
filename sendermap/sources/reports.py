"""Report addresses: where the domain sends its DMARC and TLS reports. A service found only
here receives reports; it does not send the domain's mail."""

from __future__ import annotations

import asyncio

from ..dns import Answer
from ..model import Claim, Evidence, Finding, Gap, GapKind, Kind, Observed, Severity, Unknown
from . import Context


def versioned(answer: Answer, version: str) -> list[str]:
    """The records whose first tag is v=<version>, as a receiver counts them (RFC 9989 for DMARC,
    RFC 8460 for TLS-RPT): the tag name and value are not case sensitive here, spaces around the
    "=" and the ";" are allowed, and v=DMARC10 is not v=DMARC1."""
    found = []
    for record in answer.records:
        key, sep, value = record.split(";", 1)[0].partition("=")
        if sep and key.strip().lower() == "v" and value.strip().lower() == version:
            found.append(record)
    return found


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
    gaps: list[Gap] = []
    findings: list[Finding] = []
    for answer, record_name, version, tags, kind, label in (
        (dmarc, "DMARC", "dmarc1", ("rua", "ruf"), Kind.DMARC_REPORTS, "DMARC reports go to"),
        (tlsrpt, "TLS-RPT", "tlsrptv1", ("rua",), Kind.TLSRPT_REPORTS, "TLS reports go to"),
    ):
        if not answer.answered:
            asked = f"{record_name}: TXT at {answer.name}"
            gaps.append(Gap(asked, answer.status.value, GapKind.REPORTS, 1))
        records = versioned(answer, version)
        if len(records) > 1:
            findings.append(_several(ctx, answer.name, record_name, records))
            continue
        for record in records:
            for host in report_domains(record, tags):
                evidence = Evidence(answer.name, "TXT", record, ctx.checked_at)
                if service := ctx.catalog.reporting(host):
                    claims.append(Claim(service, kind, ctx.domain, evidence))
                elif not (host == ctx.domain or host.endswith("." + ctx.domain)):
                    unknowns.append(Unknown(label, host, ctx.domain, evidence))
    return Observed(tuple(claims), tuple(unknowns), tuple(findings), gaps=tuple(gaps))


def _several(ctx: Context, name: str, record_name: str, records: list[str]) -> Finding:
    """More than one record at the name: a receiver applies none, so no report address in them
    is used and none is credited."""
    return Finding(
        Severity.RISK,
        f"{name} publishes {len(records)} {record_name} records",
        f"A receiver that finds more than one {record_name} record at a name uses none of them, "
        "so the report addresses in them receive nothing and none is credited here. Publish "
        "one record.",
        tuple(Evidence(name, "TXT", r, ctx.checked_at) for r in records),
    )
