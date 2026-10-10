"""The DKIM scan: who holds each key, and what the keys say."""

from conftest import Zone, context

from sendermap.model import Kind, Severity
from sendermap.sources import dkim

KEY_2048 = "v=DKIM1; k=rsa; p=" + "A" * 392
KEY_1024 = "v=DKIM1; k=rsa; p=" + "A" * 216


async def scan(zone: Zone, selectors, backed=None):
    return await dkim.collect(context(zone), "example.com", selectors, backed or {})


async def test_a_key_behind_a_cname_is_the_service_hosting_it():
    zone = (
        Zone()
        .alias("k2._domainkey.example.com", "dkim2.mcsv.net")
        .add("dkim2.mcsv.net", "TXT", KEY_2048)
    )
    observed = await scan(zone, ["k2"])
    assert [(c.service, c.kind) for c in observed.claims] == [("Mailchimp", Kind.DKIM_CNAME)]


async def test_a_key_known_by_name_is_only_likely():
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["mandrill"])
    assert [(c.service, c.kind) for c in observed.claims] == [("Mandrill", Kind.DKIM_NAME)]


async def test_a_key_nobody_can_name_is_listed():
    zone = Zone().add("default._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["default"])
    assert observed.claims == ()
    assert [u.value for u in observed.unknowns] == ["default"]


async def test_a_retired_key_is_an_account_trace():
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", "v=DKIM1; p=")
    observed = await scan(zone, ["mandrill"])
    assert [c.kind for c in observed.claims] == [Kind.DKIM_RETIRED]


async def test_a_cname_to_nowhere_is_a_risk():
    zone = Zone().alias("s1._domainkey.example.com", "s1.domainkey.u1.wl1.sendgrid.net")
    observed = await scan(zone, ["s1"])
    assert [c.kind for c in observed.claims] == [Kind.DKIM_DANGLING]
    assert observed.findings[0].severity is Severity.RISK


async def test_a_wildcard_makes_every_key_meaningless():
    zone = Zone().add("*._domainkey.example.com", "TXT", KEY_2048)
    observed = await scan(zone, ["k1", "s1"])
    assert observed.claims == ()
    assert "wildcard" in observed.findings[0].detail
    assert observed.findings[0].evidence[0].name == "*._domainkey.example.com"


async def test_a_1024_bit_key_is_flagged():
    zone = Zone().add("mandrill._domainkey.example.com", "TXT", KEY_1024)
    observed = await scan(zone, ["mandrill"])
    assert any("1024-bit" in f.title for f in observed.findings)


async def test_failed_lookups_are_a_gap():
    zone = Zone(failing={"k1._domainkey.example.com"})
    observed = await scan(zone, ["k1"])
    assert observed.gaps
