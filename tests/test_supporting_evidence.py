"""A claim carries every record that decided it, and an unknown carries the record behind it."""

from conftest import CHECKED, Zone, context
from test_evidence import mapped_map
from test_networks import owner

from sendermap.model import Claim, Evidence, Kind
from sendermap.render import markdown
from sendermap.sources import dkim, mx, networks, reports, spf

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392
TERM = Evidence("example.com", "TXT", "ip4:54.240.8.0/21", CHECKED)


async def test_a_range_credited_by_a_published_range_carries_the_publishing_term() -> None:
    zone = Zone().add("amazonses.com", "TXT", "v=spf1 ip4:54.240.0.0/18 -all")
    observed = await networks.collect(context(zone), "example.com", [("54.240.8.0/21", TERM)])
    (claim,) = observed.claims
    assert claim.evidence == TERM
    assert claim.supporting == (Evidence("amazonses.com", "TXT", "ip4:54.240.0.0/18", CHECKED),)


async def test_a_range_credited_by_its_network_carries_team_cymrus_answers() -> None:
    zone = owner(Zone(), "198.2.128.1", "AS14782", "THEROCKETSCIENCEGROUP - MailChimp, US")
    term = Evidence("example.com", "TXT", "ip4:198.2.128.0/24", CHECKED)
    observed = await networks.collect(context(zone), "example.com", [("198.2.128.0/24", term)])
    (claim,) = observed.claims
    assert claim.evidence == term
    assert [(e.name, e.value) for e in claim.supporting] == [
        ("1.128.2.198.origin.asn.cymru.com", "14782 | 198.2.128.1/24 | US | arin | 2020-01-01"),
        (
            "as14782.asn.cymru.com",
            "14782 | US | arin | 2005-01-01 | THEROCKETSCIENCEGROUP - MailChimp, US",
        ),
    ]


async def test_a_key_credited_through_a_backed_selector_carries_the_backing_record() -> None:
    include = Evidence("example.com", "TXT", "include:mailgun.org", CHECKED)
    backing = Claim("Mailgun", Kind.SPF_INCLUDE, "example.com", include)
    zone = Zone().add("k1._domainkey.example.com", "TXT", KEY)
    observed = await dkim.collect(context(zone), "example.com", ["k1"], {"k1": backing})
    (claim,) = observed.claims
    assert (claim.service, claim.kind, claim.supporting) == ("Mailgun", Kind.DKIM_NAME, (include,))


async def test_a_key_named_or_served_by_cname_needs_no_supporting_record() -> None:
    zone = (
        Zone()
        .add("mandrill._domainkey.example.com", "TXT", KEY)
        .alias("k2._domainkey.example.com", "dkim2.mcsv.net")
        .add("dkim2.mcsv.net", "TXT", KEY)
    )
    backing = Claim("Mailgun", Kind.SPF_INCLUDE, "example.com", TERM)
    observed = await dkim.collect(context(zone), "example.com", ["mandrill", "k2"], {"k2": backing})
    assert {(c.service, c.supporting) for c in observed.claims} == {
        ("Mandrill", ()),
        ("Mailchimp", ()),
    }


async def test_every_unknown_carries_the_record_that_shows_it() -> None:
    zone = (
        Zone()
        .add("default._domainkey.example.com", "TXT", KEY)
        .add("example.com", "MX", "10 mx.unknown-host.example")
        .add("example.com", "TXT", "v=spf1 include:_spf.sendergen.com -all")
        .add("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:r@reports.example.org")
    )
    ctx = context(zone)
    (found, _), mail, keys, addresses = (
        await spf.collect(ctx, "example.com"),
        await mx.collect(ctx, "example.com"),
        await dkim.collect(ctx, "example.com", ["default"], {}),
        await reports.collect(ctx),
    )
    unknowns = {u.value: u.evidence for o in (found, mail, keys, addresses) for u in o.unknowns}
    assert {value: (e.name, e.rtype) for value, e in unknowns.items()} == {
        "_spf.sendergen.com": ("example.com", "TXT"),
        "mx.unknown-host.example": ("example.com", "MX"),
        "default": ("default._domainkey.example.com", "TXT"),
        "reports.example.org": ("_dmarc.example.com", "TXT"),
    }
    assert all(e.checked_at == CHECKED for e in unknowns.values())


async def test_markdown_shows_supporting_records_without_breaking_the_table() -> None:
    text = markdown.render(await mapped_map())
    (row,) = [line for line in text.splitlines() if line.startswith("| Mailchimp ")]
    assert "cymru" not in row  # the row summarises; records print only with evidence
    assert row.count("|") - row.count("\\|") == 6  # five cells, nothing split
    full = markdown.render(await mapped_map(), evidence=True)
    assert "via 1.100.51.198.origin.asn.cymru.com TXT 14782 | 198.51.100.0/24" in full
    assert "- DKIM key: `default`, from `default._domainkey.mapped.test TXT v=DKIM1;" in text
