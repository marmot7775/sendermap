"""Report addresses: where the domain sends its DMARC and TLS reports. A service found only
here receives reports; it does not send the domain's mail.

A DMARC report address outside the domain receives reports only when its domain says it takes
them for this one (RFC 9990 section 4 for aggregate reports, RFC 9991 section 5 for failure
reports): a v=DMARC1 record at `<domain>._report._dmarc.<report domain>`. Without one, receivers
ignore the address, so it is a finding and not credited. TLS-RPT (RFC 8460) has no such check."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ..dns import Answer
from ..model import Claim, Evidence, Finding, Gap, GapKind, Kind, Observed, Severity, Unknown
from . import Context, negative

DMARC_TAGS = ("rua", "ruf")
_KINDS = {"rua": "aggregate", "ruf": "failure"}
NAME_LIMIT = 253  # octets in a DNS name, without the final dot


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
    observed = Observed()
    for answer, record_name, version, tags, kind, label in (
        (dmarc, "DMARC", "dmarc1", DMARC_TAGS, Kind.DMARC_REPORTS, "DMARC reports go to"),
        (tlsrpt, "TLS-RPT", "tlsrptv1", ("rua",), Kind.TLSRPT_REPORTS, "TLS reports go to"),
    ):
        if not answer.answered:
            asked = f"{record_name}: TXT at {answer.name}"
            observed += Observed(gaps=(Gap(asked, answer.status.value, GapKind.REPORTS, 1),))
        records = versioned(answer, version)
        if len(records) > 1:
            observed += Observed(findings=(_several(ctx, answer.name, record_name, records),))
            continue
        for record in records:
            evidence = Evidence(answer.name, "TXT", record, ctx.checked_at)
            hosts = [h for h in report_domains(record, tags) if not _own(h, ctx.domain)]
            checks = await asyncio.gather(*(_authorized(ctx, h, record, kind) for h in hosts))
            for host, check in zip(hosts, checks, strict=True):
                observed += _credit(
                    ctx, host, kind=kind, label=label, evidence=evidence, check=check
                )
    return observed


def _own(host: str, domain: str) -> bool:
    """The domain itself, a name under it, or a name above it: one organizational domain, so
    no authorization is needed and nothing outside the domain is credited."""
    return host == domain or host.endswith("." + domain) or domain.endswith("." + host)


@dataclass(frozen=True, slots=True)
class _Check:
    """What the external destination check found for one report host. `sent` is False when
    receivers send it no report; `supporting` holds the record that authorizes it, `finding`
    says why it is not, or may not be, authorized, and `gap` that the check could not be read."""

    sent: bool = True
    supporting: tuple[Evidence, ...] = ()
    finding: Finding | None = None
    gap: Gap | None = None


async def _authorized(ctx: Context, host: str, record: str, kind: Kind) -> _Check:
    """Run RFC 9990 section 4 for one outside DMARC report host; TLS-RPT hosts need none."""
    if kind is not Kind.DMARC_REPORTS:
        return _Check()
    name = f"{ctx.domain}._report._dmarc.{host}"
    policy = Evidence(f"_dmarc.{ctx.domain}", "TXT", record, ctx.checked_at)
    if len(name) > NAME_LIMIT:
        why = f"{name} is longer than a DNS name can be, so it cannot be asked"
        return _Check(sent=False, finding=_unauthorized(ctx, host, why, (policy,)))
    answer = await ctx.dns.txt(name)
    if not answer.answered:
        asked = f"DMARC report authorization: TXT at {name}"
        return _Check(gap=Gap(asked, answer.status.value, GapKind.REPORTS, 1))
    granted = versioned(answer, "dmarc1")
    if not granted:
        return _denied(ctx, host, name, (policy, negative(answer, ctx.checked_at)))
    return _granted(ctx, host, name, policy, granted)


def _denied(ctx: Context, host: str, name: str, shown: tuple[Evidence, ...]) -> _Check:
    """No v=DMARC1 record at the authorization name: not sent, unless the host may share the
    domain's organizational domain, where none is needed."""
    if _may_share_parent(host, ctx.domain):
        return _Check(finding=_unsure(ctx, host, name, shown))
    why = f"{name} publishes no v=DMARC1 record"
    return _Check(sent=False, finding=_unauthorized(ctx, host, why, shown))


def _granted(ctx: Context, host: str, name: str, policy: Evidence, granted: list[str]) -> _Check:
    """Authorized, unless the authorizing record points a kind of report at another host."""
    record = policy.value
    supporting = tuple(Evidence(name, "TXT", r, ctx.checked_at) for r in granted)
    wanted = [t for t in DMARC_TAGS if host in report_domains(record, (t,))]
    elsewhere = [t for t in wanted if _redirected(granted, t, host)]
    if not elsewhere:
        return _Check(supporting=supporting)
    why = (
        f"{name}, which authorizes it, points {' and '.join(elsewhere)} at another host, and "
        "receivers then send to neither"
    )
    which = "DMARC" if elsewhere == wanted else f"DMARC {_KINDS[elsewhere[0]]}"
    finding = _unauthorized(ctx, host, why, (policy, *supporting), which)
    return _Check(sent=elsewhere != wanted, supporting=supporting, finding=finding)


def _redirected(granted: list[str], tag: str, host: str) -> bool:
    """Whether an authorizing record overrides `tag` with an address at another host (RFC 9990
    section 4, step 9): receivers then send that kind of report nowhere."""
    return any(h != host for r in granted for h in report_domains(r, (tag,)))


def _may_share_parent(host: str, domain: str) -> bool:
    """Whether the two names end in the same two labels, so they may be one organizational
    domain (two names under example.com, or under co.uk), which this map does not work out."""
    return host.split(".")[-2:] == domain.split(".")[-2:]


def _credit(
    ctx: Context, host: str, *, kind: Kind, label: str, evidence: Evidence, check: _Check
) -> Observed:
    """A report host as the map shows it: credited unless receivers send it nothing, with the
    check's finding or gap beside it."""
    observed = Observed(
        findings=(check.finding,) if check.finding else (),
        gaps=(check.gap,) if check.gap else (),
    )
    if not check.sent:
        return observed
    if service := ctx.catalog.reporting(host):
        claim = Claim(service, kind, ctx.domain, evidence, check.supporting)
        return observed + Observed(claims=(claim,))
    return observed + Observed(unknowns=(Unknown(label, host, ctx.domain, evidence),))


def _unauthorized(
    ctx: Context, host: str, why: str, evidence: tuple[Evidence, ...], which: str = "DMARC"
) -> Finding:
    """Receivers send no report of this kind to the host."""
    return Finding(
        Severity.WARNING,
        f"{which} reports for {ctx.domain} to {host} are not authorized",
        f"The DMARC record asks for reports at {host}, outside the domain, but {why}. Receivers "
        "that check (RFC 9990 section 4, RFC 9991 section 5) ignore the address and send it "
        "nothing. The report service publishes the authorization record, or the address "
        "changes to one that takes the domain's reports.",
        evidence,
    )


def _unsure(ctx: Context, host: str, name: str, evidence: tuple[Evidence, ...]) -> Finding:
    """No authorization record, at a host that may share the domain's organizational domain,
    where none is needed."""
    return Finding(
        Severity.NOTE,
        f"DMARC reports for {ctx.domain} to {host} may not be authorized",
        f"{name} publishes no v=DMARC1 record. That is needed only if {host} is in another "
        f"organizational domain than {ctx.domain} (RFC 9990 section 4), and this map does not "
        "work out organizational domains. If they are separate, receivers send the address "
        "nothing.",
        evidence,
    )


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
