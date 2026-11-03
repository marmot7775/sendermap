"""DMARC report addresses outside the domain: credited only when the report domain authorizes
them (RFC 9990 section 4, RFC 9991 section 5), and said plainly when it does not or could not
be read."""

from conftest import Zone, context

from sendermap.model import Kind, Observed, Severity
from sendermap.sources import reports

AGARI = "rua=mailto:x@rua.agari.com"
GRANT = "example.com._report._dmarc.rua.agari.com"


def dmarc(tags: str, domain: str = "example.com") -> Zone:
    return Zone().add(f"_dmarc.{domain}", "TXT", f"v=DMARC1; p=none; {tags}")


async def collect(zone: Zone, domain: str = "example.com") -> Observed:
    return await reports.collect(context(zone, domain))


def credited(observed: Observed) -> list[str]:
    claims = [c.service for c in observed.claims if c.kind is Kind.DMARC_REPORTS]
    return claims + [u.value for u in observed.unknowns]


async def test_an_authorized_service_is_credited_with_the_record_that_authorizes_it() -> None:
    observed = await collect(dmarc(AGARI).add(GRANT, "TXT", "v=DMARC1;"))
    (claim,) = observed.claims
    assert claim.service == "Agari"
    assert [(e.name, e.value) for e in claim.supporting] == [(GRANT, "v=DMARC1;")]
    assert observed.findings == () and observed.gaps == ()


async def test_a_wildcard_authorization_counts() -> None:
    zone = dmarc(AGARI).add("*._report._dmarc.rua.agari.com", "TXT", "v=DMARC1")
    assert credited(await collect(zone)) == ["Agari"]


async def test_an_unauthorized_service_is_not_credited_and_is_a_warning() -> None:
    zone = dmarc(AGARI).add(GRANT, "TXT", "some other text")
    observed = await collect(zone)
    assert credited(observed) == []
    (finding,) = observed.findings
    assert finding.severity is Severity.WARNING
    assert finding.title == "DMARC reports for example.com to rua.agari.com are not authorized"
    assert f"{GRANT} publishes no v=DMARC1 record" in finding.detail
    assert [e.name for e in finding.evidence] == ["_dmarc.example.com", GRANT]


async def test_an_unknown_host_without_authorization_is_not_listed() -> None:
    observed = await collect(dmarc("rua=mailto:r@reports.example.net"))
    assert credited(observed) == []
    (finding,) = observed.findings
    assert finding.title.endswith("to reports.example.net are not authorized")
    assert finding.evidence[1].value == "no such name"


async def test_an_authorization_that_cannot_be_read_is_a_gap_and_still_credited() -> None:
    zone = Zone(failing={GRANT}).add("_dmarc.example.com", "TXT", f"v=DMARC1; p=none; {AGARI}")
    observed = await collect(zone)
    assert observed.findings == ()
    assert credited(observed) == ["Agari"]
    (gap,) = observed.gaps
    assert gap.asked == f"DMARC report authorization: TXT at {GRANT}"
    assert gap.happened == "lookup failed"


async def test_an_address_in_the_domain_or_above_it_needs_no_authorization() -> None:
    zone = dmarc("rua=mailto:a@example.com,mailto:b@reports.mail.example.com", "mail.example.com")
    observed = await collect(zone, "mail.example.com")
    assert observed.findings == () and credited(observed) == []
    assert not [name for name, _ in zone.asked if "_report._dmarc" in name]


async def test_a_sibling_name_without_authorization_is_a_note_and_still_listed() -> None:
    # a.example.com and b.example.com may be one organizational domain, where none is needed.
    observed = await collect(dmarc("rua=mailto:r@b.example.com", "a.example.com"), "a.example.com")
    assert credited(observed) == ["b.example.com"]
    (finding,) = observed.findings
    assert finding.severity is Severity.NOTE
    assert finding.title == "DMARC reports for a.example.com to b.example.com may not be authorized"


async def test_an_override_to_another_host_sends_to_neither() -> None:
    # RFC 9990 section 4, step 9 and the paragraph after it.
    zone = dmarc(AGARI).add(GRANT, "TXT", "v=DMARC1; rua=mailto:y@elsewhere.example.org")
    observed = await collect(zone)
    assert credited(observed) == []
    (finding,) = observed.findings
    assert finding.title == "DMARC reports for example.com to rua.agari.com are not authorized"
    assert "points rua at another host" in finding.detail


async def test_an_override_at_the_same_host_is_authorized() -> None:
    zone = dmarc(AGARI).add(GRANT, "TXT", "v=DMARC1; rua=mailto:other@rua.agari.com")
    observed = await collect(zone)
    assert credited(observed) == ["Agari"] and observed.findings == ()


async def test_a_failure_report_override_elsewhere_leaves_aggregate_reports() -> None:
    zone = dmarc(f"{AGARI}; ruf=mailto:f@rua.agari.com").add(
        GRANT, "TXT", "v=DMARC1; ruf=mailto:f@elsewhere.example.org"
    )
    observed = await collect(zone)
    assert credited(observed) == ["Agari"]
    (finding,) = observed.findings
    assert finding.title == (
        "DMARC failure reports for example.com to rua.agari.com are not authorized"
    )


async def test_a_name_too_long_to_ask_is_not_authorized() -> None:
    domain = ".".join(["a" * 60] * 3) + ".com"
    host = ".".join(["b" * 40] * 2) + ".net"
    observed = await collect(dmarc(f"rua=mailto:r@{host}", domain), domain)
    assert credited(observed) == []
    (finding,) = observed.findings
    assert "longer than a DNS name can be" in finding.detail


async def test_tls_report_addresses_need_no_authorization() -> None:
    zone = Zone().add("_smtp._tls.example.com", "TXT", "v=TLSRPTv1; rua=mailto:z@uriports.com")
    observed = await collect(zone)
    assert [c.service for c in observed.claims] == ["URIports"]
    assert not [name for name, _ in zone.asked if "_report._dmarc" in name]
