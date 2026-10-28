"""Rule 4: each label says what its evidence shows and no more."""

import httpx
from conftest import CHECKED, Zone, context
from rich.console import Console

from sendermap import map_domain
from sendermap.model import Evidence, KeyPrint, Kind, Observed, Role, Severity, Tier, Unknown
from sendermap.render import NetworkGroup, grouped_unknowns, html, markdown, text
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
    zone = Zone().public("mta-sts.example.com").add("_mta-sts.example.com", "TXT", "v=STSv1; id=1")
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
        .add("sendgrid.net", "TXT", "v=spf1 ip4:192.0.2.0/24 -all")
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


async def test_the_key_flags_say_what_each_tag_means() -> None:
    p = "MCowBQYDK2VwAyEA" + "A" * 28
    zone = (
        Zone()
        .add("k1._domainkey.example.com", "TXT", f"v=DKIM1; t=y; p={p}")
        .add("k2._domainkey.example.com", "TXT", f"v=DKIM1; h=sha1; p={p}")
        .add("k3._domainkey.example.com", "TXT", f"v=DKIM1; s=tlsrpt; p={p}")
        .add("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=dsa; p={p}")
        .add("s2._domainkey.example.com", "TXT", "v=DKIM1; k=ed25519; p=" + "A" * 40)
    )
    observed = await scan(zone, ["k1", "k2", "k3", "s1", "s2"])
    titles = {f.title: f.detail for f in observed.findings}
    assert titles["The k1 key at example.com is in testing mode"].startswith(
        "t=y tells verifiers to treat mail signed with it like unsigned mail (RFC 6376 section "
        "3.6.1), so the key adds nothing until the flag is removed."
    )
    assert "RFC 8301 (section 3.1)" in titles["The k2 key at example.com allows SHA-1 only"]
    assert (
        "verifiers ignore the record for email (RFC 6376 section 3.6.1)"
        in (titles["The k3 key at example.com is not for email"])
    )
    assert "cannot be used" in titles["The s1 key at example.com has an unknown key type, k=dsa"]
    assert "decodes to 30 bytes" in titles["The s2 key at example.com is a malformed Ed25519 key"]


def test_the_same_key_note_names_both_selectors_and_where() -> None:
    def seen(selector: str, where: str) -> KeyPrint:
        name = f"{selector}._domainkey.{where}"
        return KeyPrint(selector, where, "0123456789abcdef", Evidence(name, "TXT", KEY, CHECKED))

    (here,) = dkim.same_keys([seen("k1", "example.com"), seen("s1", "example.com")])
    assert here.title == "The k1 and s1 keys at example.com are the same key"
    assert [e.name for e in here.evidence] == [
        "k1._domainkey.example.com",
        "s1._domainkey.example.com",
    ]
    (apart,) = dkim.same_keys([seen("k1", "example.com"), seen("s1", "mail.example.com")])
    assert apart.title == (
        "The k1 key at example.com and the s1 key at mail.example.com are the same key"
    )
    assert dkim.same_keys([seen("k1", "example.com"), seen("k1", "example.com")]) == ()


def announced(zone: Zone, ip: str, asn: str, name: str) -> Zone:
    reverse = ".".join(reversed(ip.split(".")))
    zone.add(f"{reverse}.origin.asn.cymru.com", "TXT", f"{asn[2:]} | {ip}/24 | US | arin | 2020")
    return zone.add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005 | {name}")


async def test_unrecognised_ranges_are_grouped_by_network_in_the_views(
    offline: httpx.AsyncClient,
) -> None:
    spf_record = (
        "v=spf1 ip4:35.159.219.224/28 ip4:18.199.180.160/27 ip4:35.80.141.6 "
        "ip4:203.0.113.0/24 ip4:198.18.0.0/24 -all"
    )
    zone = Zone().add("acme.test", "TXT", spf_record).add("acme.test", "MX", "10 mx.unheard.test")
    for ip in ("35.159.219.225", "18.199.180.161", "35.80.141.6"):
        announced(zone, ip, "AS16509", "AMAZON-02 - Amazon.com, Inc., US")
    announced(zone, "198.18.0.1", "AS64500", "EXAMPLE-NET, US")
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    # The data keeps one Unknown per range.
    assert len([u for u in result.to_dict()["unknowns"] if u["what"].startswith("IP")]) == 5

    console = Console(record=True, width=200)
    text.render(result, console)
    shown = console.export_text()
    assert "  2 ranges and 1 address in AS16509 (Amazon Web Services)\n" in shown
    assert "    35.159.219.224/28, 18.199.180.160/27, 35.80.141.6\n" in shown
    assert "acme.test TXT ip4:35.159.219.224/28\n    + 2 more\n" in shown
    assert "IP range in SPF: 203.0.113.0/24 (no one network announces it)" in shown
    assert "IP range in SPF: 198.18.0.0/24 (AS64500, EXAMPLE-NET, US)" in shown
    assert "mail server: mx.unheard.test" in shown

    console = Console(record=True, width=200)
    text.render(result, console, evidence=True)
    shown = console.export_text()
    assert "+ 2 more" not in shown
    assert (
        "acme.test TXT ip4:18.199.180.160/27" in shown and "acme.test TXT ip4:35.80.141.6" in shown
    )

    md = markdown.render(result)
    assert (
        "- 2 ranges and 1 address in AS16509 (Amazon Web Services): `35.159.219.224/28`, "
        "`18.199.180.160/27`, `35.80.141.6`, from `acme.test TXT ip4:35.159.219.224/28` + 2 more"
    ) in md
    full = markdown.render(result, evidence=True)
    assert "  - `acme.test TXT ip4:35.80.141.6`" in full

    # The web page shows the same group, the first record and the rest inside details.
    page = html.html(result)
    assert (
        '<li>2 ranges and 1 address in AS16509 (Amazon Web Services): <span class="mono">'
        "35.159.219.224/28, 18.199.180.160/27, 35.80.141.6</span>\n"
        '<span class="ev mono">acme.test TXT ip4:35.159.219.224/28</span>\n'
        '<details class="records"><summary>2 more records</summary>'
    ) in page


def test_a_network_group_says_what_it_holds_and_lists_publishers_once() -> None:
    def unknown(what: str, value: str) -> Unknown:
        return Unknown(what, value, "acme.test", Evidence("acme.test", "TXT", "ip4:x", CHECKED))

    listed = "; listed by Google Workspace and HubSpot)"
    (group,) = grouped_unknowns(
        (
            unknown("IP range in SPF", f"74.125.0.0/16 (AS15169, Google{listed}"),
            unknown("IP range in SPF", f"209.85.128.0/17 (AS15169, Google{listed}"),
        )
    )
    assert isinstance(group, NetworkGroup)
    assert group.heading() == "2 ranges in AS15169 (Google); listed by Google Workspace and HubSpot"
    # Another list of publishers is another group; one range alone in its network stays single.
    grouped = grouped_unknowns(
        (
            unknown("IP address in SPF", "192.0.2.1 (AS64500, SENDGRID - SendGrid, Inc., US)"),
            unknown("IP address in SPF", "192.0.2.9 (AS64500, SENDGRID - SendGrid, Inc., US)"),
            unknown(
                "IP range in SPF",
                "192.0.2.0/24 (AS64500, SENDGRID - SendGrid, Inc., US; listed by HubSpot)",
            ),
        )
    )
    assert [g.heading() if isinstance(g, NetworkGroup) else g.value for g in grouped] == [
        "2 addresses in AS64500 (SENDGRID - SendGrid, Inc., US)",
        "192.0.2.0/24 (AS64500, SENDGRID - SendGrid, Inc., US; listed by HubSpot)",
    ]
