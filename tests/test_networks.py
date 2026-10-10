"""Naming the services behind raw IP ranges in SPF."""

from conftest import CHECKED, Zone, context

from sendermap.model import Evidence, Kind
from sendermap.sources import networks

EV = Evidence("example.com", "TXT", "ip4:...", CHECKED)


def owner(zone: Zone, ip: str, asn: str, name: str) -> Zone:
    reverse = ".".join(reversed(ip.split(".")))
    zone.add(
        f"{reverse}.origin.asn.cymru.com", "TXT", f"{asn[2:]} | {ip}/24 | US | arin | 2020-01-01"
    )
    zone.add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005-01-01 | {name}")
    return zone


async def test_a_range_inside_one_services_published_range_is_that_service():
    zone = Zone().add("amazonses.com", "TXT", "v=spf1 ip4:54.240.0.0/18 -all")
    observed = await networks.collect(context(zone), "example.com", [("54.240.8.0/21", EV)])
    assert [(c.service, c.kind) for c in observed.claims] == [("Amazon SES", Kind.SPF_NETWORK)]


async def test_only_a_services_own_ranges_count():
    # Atlassian's record includes SendGrid's: those ranges stay SendGrid's.
    zone = (
        Zone()
        .add("_spf.atlassian.net", "TXT", "v=spf1 include:sendgrid.net -all")
        .add("sendgrid.net", "TXT", "v=spf1 ip4:167.89.0.0/17 -all")
    )
    observed = await networks.collect(context(zone), "example.com", [("167.89.0.0/17", EV)])
    assert [c.service for c in observed.claims] == ["SendGrid"]


async def test_a_shared_range_on_a_cloud_network_is_unknown_and_lists_its_publishers():
    # 74.125.0.0/16 is listed by Google Workspace and HubSpot, announced by Google.
    zone = (
        Zone()
        .add("_spf.google.com", "TXT", "v=spf1 ip4:74.125.0.0/16 ~all")
        .add("hubspot.com", "TXT", "v=spf1 ip4:74.125.0.0/16 -all")
    )
    for ip in ("74.125.0.1", "74.125.128.1", "74.125.192.1"):
        owner(zone, ip, "AS15169", "GOOGLE - Google LLC, US")
    observed = await networks.collect(context(zone), "example.com", [("74.125.0.0/16", EV)])
    assert observed.claims == ()
    assert [u.value for u in observed.unknowns] == [
        "74.125.0.0/16 (AS15169, Google; listed by Google Workspace and HubSpot)"
    ]


async def test_a_services_own_network_names_it():
    zone = owner(Zone(), "198.2.128.1", "AS14782", "THEROCKETSCIENCEGROUP - MailChimp, US")
    observed = await networks.collect(context(zone), "example.com", [("198.2.128.0/24", EV)])
    assert [c.service for c in observed.claims] == ["Mailchimp"]


async def test_a_large_range_follows_the_majority_of_its_blocks():
    # Its first /24 is announced by Amazon, as with SendGrid's 149.72.0.0/16; the other two
    # samples by Mailchimp.
    zone = owner(Zone(), "198.2.128.1", "AS14618", "AMAZON-AES - Amazon.com, Inc., US")
    for ip in ("198.2.160.1", "198.2.176.1"):
        owner(zone, ip, "AS14782", "THEROCKETSCIENCEGROUP - MailChimp, US")
    observed = await networks.collect(context(zone), "example.com", [("198.2.128.0/18", EV)])
    assert [c.service for c in observed.claims] == ["Mailchimp"]


async def test_a_cloud_is_never_credited_to_a_service():
    zone = owner(Zone(), "35.80.141.6", "AS16509", "AMAZON-02 - Amazon.com, Inc., US")
    observed = await networks.collect(context(zone), "example.com", [("35.80.141.6/32", EV)])
    assert observed.claims == ()
    assert "Amazon Web Services" in observed.unknowns[0].value
    assert observed.unknowns[0].what == "IP address in SPF"


async def test_a_services_ranges_are_read_through_the_maps_own_lookups():
    zone = Zone().add("amazonses.com", "TXT", "v=spf1 ip4:54.240.0.0/18 -all")
    ctx = context(zone)
    await networks.collect(ctx, "example.com", [("54.240.8.0/21", EV)])
    assert ("amazonses.com", "TXT") in zone.asked
    assert ctx.dns.count == len(set(zone.asked))


async def test_a_service_whose_ranges_could_not_be_read_is_a_gap_naming_it():
    zone = Zone(failing={"amazonses.com"})
    observed = await networks.collect(context(zone), "example.com", [("54.240.8.0/21", EV)])
    assert "published ranges: SPF of Amazon SES" in [g.asked for g in observed.gaps]
