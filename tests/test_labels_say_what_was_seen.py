"""Rule 4: each label says what its evidence shows and no more."""

import httpx
from conftest import CHECKED, Zone, context

from sendermap import map_domain
from sendermap.model import Kind, Observed, Role, Severity, Tier
from sendermap.sources import Context, dkim, mta_sts, mx, spf

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392


async def scan(zone: Zone, selectors: list[str]) -> Observed:
    return await dkim.collect(context(zone), "example.com", selectors, {})


async def test_a_dkim_record_with_no_p_tag_is_malformed_not_revoked() -> None:
    zone = (
        Zone()
        .add("mandrill._domainkey.example.com", "TXT", "v=DKIM1; k=rsa; ap=MIGfMA0")
        .add("k1._domainkey.example.com", "TXT", "v=DKIM1; p=")
    )
    observed = await scan(zone, ["mandrill", "k1"])
    (finding,) = observed.findings
    assert finding.severity is Severity.WARNING and "no p= tag" in finding.title
    assert finding.evidence[0].value == "v=DKIM1; k=rsa; ap=MIGfMA0"
    assert [(c.service, c.kind) for c in observed.claims] == [("Mailchimp", Kind.DKIM_REVOKED)]


async def test_a_wildcard_record_that_is_not_a_key_is_not_read_as_a_malformed_key() -> None:
    zone = (
        Zone()
        .add("*._domainkey.example.com", "TXT", "hello")
        .add("k1._domainkey.example.com", "TXT", KEY)
    )
    observed = await scan(zone, ["k1", "s1", "s2"])
    assert observed.findings == ()
    assert [c.kind for c in observed.claims] == [Kind.DKIM_NAME]


async def test_a_reporting_service_has_no_tier(offline: httpx.AsyncClient) -> None:
    zone = Zone().add("_dmarc.acme.test", "TXT", "v=DMARC1; p=none; rua=mailto:x@rua.agari.com")
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    (agari,) = result.reporting
    assert agari.role is Role.REPORTING and agari.tier is None
    assert result.to_dict()["services"][0]["tier"] is None


async def test_an_mta_sts_mx_line_is_configured_not_in_use() -> None:
    zone = Zone().add("_mta-sts.example.com", "TXT", "v=STSv1; id=1")
    policy = "version: STSv1\nmode: testing\nmx: *.mail.protection.outlook.com\n"

    def serve(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=policy)

    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as http:
        ctx = context(zone)
        ctx = Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http)
        (claim,) = (await mta_sts.collect(ctx)).claims
    assert claim.kind is Kind.MTA_STS and claim.kind.tier is Tier.CONFIGURED


async def test_a_mailbox_mx_on_a_subdomain_is_in_use_there_only(offline: httpx.AsyncClient) -> None:
    zone = Zone().add("mail.acme.test", "MX", "1 smtp.google.com")
    (claim,) = (await mx.collect(context(zone, "acme.test"), "mail.acme.test")).claims
    assert claim.kind is Kind.SUBDOMAIN_MAILBOX and "subdomain" in claim.kind.value
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    google = next(s for s in result.senders if s.name == "Google Workspace")
    assert google.tier is Tier.CONFIGURED and google.decided_by.where == "mail.acme.test"


async def test_the_gateway_note_states_what_mx_shows_labelled_as_inference(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("acme.test", "MX", "10 us-smtp-inbound-1.mimecast.com")
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    (note,) = [f for f in result.findings if "security gateway" in f.title]
    assert note.title == "MX at acme.test points at Mimecast, a security gateway"
    assert note.detail.startswith("Inferred from the MX records:")
    assert "usually" not in note.detail
    assert [e.value for e in note.evidence] == ["10 us-smtp-inbound-1.mimecast.com"]


async def test_the_easydmarc_note_says_the_walk_read_its_record() -> None:
    zone = (
        Zone()
        .add("example.com", "TXT", "v=spf1 include:x._s.easydmarc.pro -all")
        .add("x._s.easydmarc.pro", "TXT", "v=spf1 include:sendgrid.net -all")
    )
    observed, _ = await spf.collect(context(zone), "example.com")
    assert {c.service for c in observed.claims} == {"SendGrid"}
    (note,) = observed.findings
    assert "The walk read that record" in note.detail and "do not show" not in note.detail
    unread = Zone(failing={"x._s.easydmarc.pro"}).add(
        "example.com", "TXT", "v=spf1 include:x._s.easydmarc.pro -all"
    )
    observed, _ = await spf.collect(context(unread), "example.com")
    assert "could not read it" in observed.findings[0].detail
