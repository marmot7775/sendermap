"""Naming the services behind raw IP ranges in SPF."""

import ipaddress

import httpx
from conftest import CHECKED, Zone, context

from sendermap import map_domain
from sendermap.model import Evidence, Kind, Unknown
from sendermap.render import NetworkGroup, grouped_unknowns
from sendermap.sources import networks

EV = Evidence("example.com", "TXT", "ip4:...", CHECKED)


def owner(zone: Zone, ip: str, asn: str, name: str) -> Zone:
    reverse = ".".join(reversed(ip.split(".")))
    zone.add(
        f"{reverse}.origin.asn.cymru.com", "TXT", f"{asn[2:]} | {ip}/24 | US | arin | 2020-01-01"
    )
    zone.add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005-01-01 | {name}")
    return zone


async def test_a_range_inside_one_services_published_range_is_that_service() -> None:
    zone = Zone().add("amazonses.com", "TXT", "v=spf1 ip4:54.240.0.0/18 -all")
    observed = await networks.collect(context(zone), "example.com", [("54.240.8.0/21", EV)])
    assert [(c.service, c.kind) for c in observed.claims] == [("Amazon SES", Kind.SPF_NETWORK)]


async def test_only_a_services_own_ranges_count() -> None:
    # Atlassian's record includes SendGrid's: those ranges stay SendGrid's.
    zone = (
        Zone()
        .add("_spf.atlassian.net", "TXT", "v=spf1 include:sendgrid.net -all")
        .add("sendgrid.net", "TXT", "v=spf1 ip4:167.89.0.0/17 -all")
    )
    observed = await networks.collect(context(zone), "example.com", [("167.89.0.0/17", EV)])
    assert [c.service for c in observed.claims] == ["SendGrid"]


async def test_a_shared_range_on_a_cloud_network_is_unknown_and_lists_its_publishers() -> None:
    # A range listed by Google Workspace and HubSpot, announced by Google.
    zone = (
        Zone()
        .add("_spf.google.com", "TXT", "v=spf1 ip4:74.125.0.0/16 ~all")
        .add("hubspotemail.net", "TXT", "v=spf1 ip4:74.125.0.0/16 -all")
    )
    for ip in ("74.125.0.1", "74.125.128.1", "74.125.192.1"):
        owner(zone, ip, "AS15169", "GOOGLE - Google LLC, US")
    observed = await networks.collect(context(zone), "example.com", [("74.125.0.0/16", EV)])
    assert observed.claims == ()
    assert [u.value for u in observed.unknowns] == [
        "74.125.0.0/16 (AS15169, Google; listed by Google Workspace and HubSpot)"
    ]


async def test_a_services_own_network_names_it() -> None:
    zone = owner(Zone(), "198.2.128.1", "AS14782", "THEROCKETSCIENCEGROUP - MailChimp, US")
    observed = await networks.collect(context(zone), "example.com", [("198.2.128.0/24", EV)])
    assert [c.service for c in observed.claims] == ["Mailchimp"]


async def test_a_range_inside_sendgrids_network_is_sendgrid_by_team_cymrus_answers() -> None:
    # A flattened record copies a range SendGrid and HubSpot both publish, so the network decides.
    zone = (
        Zone()
        .add("sendgrid.net", "TXT", "v=spf1 ip4:223.165.113.0/24 -all")
        .add("hubspotemail.net", "TXT", "v=spf1 ip4:223.165.113.0/24 -all")
    )
    owner(zone, "223.165.113.1", "AS11377", "SENDGRID - SendGrid, Inc., US")
    observed = await networks.collect(context(zone), "example.com", [("223.165.113.0/24", EV)])
    (claim,) = observed.claims
    assert (claim.service, claim.kind, claim.evidence) == ("SendGrid", Kind.SPF_NETWORK, EV)
    assert [(e.name, e.value) for e in claim.supporting] == [
        ("1.113.165.223.origin.asn.cymru.com", "11377 | 223.165.113.1/24 | US | arin | 2020-01-01"),
        ("as11377.asn.cymru.com", "11377 | US | arin | 2005-01-01 | SENDGRID - SendGrid, Inc., US"),
    ]
    assert observed.unknowns == ()


async def test_a_large_range_follows_the_majority_of_its_blocks() -> None:
    # Its first /24 is announced by Amazon, as with SendGrid's 149.72.0.0/16; the other two
    # samples by Mailchimp.
    zone = owner(Zone(), "198.2.128.1", "AS14618", "AMAZON-AES - Amazon.com, Inc., US")
    for ip in ("198.2.160.1", "198.2.176.1"):
        owner(zone, ip, "AS14782", "THEROCKETSCIENCEGROUP - MailChimp, US")
    observed = await networks.collect(context(zone), "example.com", [("198.2.128.0/18", EV)])
    assert [c.service for c in observed.claims] == ["Mailchimp"]


async def test_a_cloud_is_never_credited_to_a_service() -> None:
    zone = owner(Zone(), "35.80.141.6", "AS16509", "AMAZON-02 - Amazon.com, Inc., US")
    observed = await networks.collect(context(zone), "example.com", [("35.80.141.6/32", EV)])
    assert observed.claims == ()
    assert "Amazon Web Services" in observed.unknowns[0].value
    assert observed.unknowns[0].what == "IP address in SPF"


async def test_a_services_ranges_are_read_through_the_maps_own_lookups() -> None:
    zone = Zone().add("amazonses.com", "TXT", "v=spf1 ip4:54.240.0.0/18 -all")
    ctx = context(zone)
    await networks.collect(ctx, "example.com", [("54.240.8.0/21", EV)])
    assert ("amazonses.com", "TXT") in zone.asked
    assert ctx.dns.count == len(set(zone.asked))


async def test_a_service_whose_ranges_could_not_be_read_is_a_gap_naming_it() -> None:
    zone = Zone(failing={"amazonses.com"})
    observed = await networks.collect(context(zone), "example.com", [("54.240.8.0/21", EV)])
    assert "published ranges: SPF of Amazon SES" in [g.asked for g in observed.gaps]


AWS = (
    ("AS16509", "AMAZON-02 - Amazon.com, Inc., US"),
    ("AS14618", "AMAZON-AES - Amazon.com, Inc., US"),
)
ORIGIN = "250.91.20.107.origin.asn.cymru.com"


def announced_twice(order: tuple[tuple[str, str], ...]) -> Zone:
    """An address Team Cymru answers with two origin records, one per prefix, added in `order`."""
    zone = Zone().add("example.com", "TXT", "v=spf1 ip4:107.20.91.250 -all")
    prefixes = {"AS16509": "107.20.0.0/14", "AS14618": "107.20.0.0/16"}
    for asn, name in order:
        zone.add(ORIGIN, "TXT", f"{asn[2:]} | {prefixes[asn]} | US | arin | 2011-05-03")
        zone.add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005-01-01 | {name}")
    return zone


async def test_an_address_announced_from_two_networks_names_both_whatever_their_order(
    offline: httpx.AsyncClient,
) -> None:
    maps = [
        await map_domain(
            "example.com",
            checked_at=CHECKED,
            resolver=announced_twice(order),
            http=offline,
            use_web=False,
            use_subdomains=False,
        )
        for order in (AWS, AWS[::-1])
    ]
    assert maps[0] == maps[1]
    assert maps[0].to_dict() | {"run": None} == maps[1].to_dict() | {"run": None}
    (unknown,) = maps[0].unknowns
    assert unknown.value == "107.20.91.250 (AS14618 and AS16509, Amazon Web Services)"
    assert maps[0].services == ()


async def test_the_owner_carries_every_cymru_answer_read() -> None:
    zone = announced_twice(AWS)
    found = await networks.owner(context(zone), ipaddress.ip_address("107.20.91.250"))
    assert found is not None
    assert found.asns == ("AS14618", "AS16509")
    assert {(e.name, e.value) for e in found.evidence} == {
        (ORIGIN, "14618 | 107.20.0.0/16 | US | arin | 2011-05-03"),
        (ORIGIN, "16509 | 107.20.0.0/14 | US | arin | 2011-05-03"),
        (
            "as14618.asn.cymru.com",
            "14618 | US | arin | 2005-01-01 | AMAZON-AES - Amazon.com, Inc., US",
        ),
        (
            "as16509.asn.cymru.com",
            "16509 | US | arin | 2005-01-01 | AMAZON-02 - Amazon.com, Inc., US",
        ),
    }


async def test_one_answer_listing_two_origins_reads_both() -> None:
    zone = Zone().add(ORIGIN, "TXT", "16509 14618 | 107.20.0.0/16 | US | arin | 2011-05-03")
    for asn, name in AWS:
        zone.add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005-01-01 | {name}")
    observed = await networks.collect(context(zone), "example.com", [("107.20.91.250", EV)])
    assert observed.unknowns[0].value == "107.20.91.250 (AS14618 and AS16509, Amazon Web Services)"


async def test_a_service_is_credited_only_when_every_announcing_network_is_its_own() -> None:
    # 198.2.128.1 answers from Mailchimp's network and from Amazon's: only one answer shows
    # Mailchimp, so nothing is credited and both networks are named.
    zone = owner(Zone(), "198.2.128.1", "AS14782", "THEROCKETSCIENCEGROUP - MailChimp, US")
    owner(zone, "198.2.128.1", "AS16509", "AMAZON-02 - Amazon.com, Inc., US")
    observed = await networks.collect(context(zone), "example.com", [("198.2.128.0/24", EV)])
    assert observed.claims == ()
    assert observed.unknowns[0].value == (
        "198.2.128.0/24 (AS14782, THEROCKETSCIENCEGROUP - MailChimp, US; "
        "AS16509, Amazon Web Services)"
    )


async def test_a_mixed_range_is_a_line_of_its_own_in_every_view() -> None:
    mixed = Unknown(
        "IP range in SPF", "207.67.38.0/24 (AS3549, LVLT; AS22606, EXACT)", "x.test", EV
    )
    other = Unknown(
        "IP range in SPF", "207.67.39.0/24 (AS3549, LVLT; AS22606, EXACT)", "x.test", EV
    )
    aws = [
        Unknown(
            "IP address in SPF", f"{ip} (AS14618 and AS16509, Amazon Web Services)", "x.test", EV
        )
        for ip in ("107.20.91.250", "3.209.231.65")
    ]
    grouped = grouped_unknowns((mixed, other, *aws))
    assert grouped[:2] == [mixed, other]
    (group,) = grouped[2:]
    assert isinstance(group, NetworkGroup)
    assert group.heading() == "2 addresses in AS14618 and AS16509 (Amazon Web Services)"


async def test_an_unnamed_network_is_no_owner() -> None:
    zone = owner(Zone(), "167.89.1.1", "AS11377", "SENDGRID - SendGrid, Inc., US")
    zone.timeouts.add(("as11377.asn.cymru.com", "TXT"))
    assert await networks.owner(context(zone), ipaddress.ip_address("167.89.1.1")) is None


async def test_a_published_range_that_does_not_parse_is_skipped() -> None:
    zone = Zone().add("amazonses.com", "TXT", "v=spf1 ip4:999.1.1.0/24 ip4:54.240.0.0/18 -all")
    published, gaps = await networks.published_ranges(context(zone))
    assert {str(n) for n, owners in published.items() if "Amazon SES" in owners} == {
        "54.240.0.0/18"
    }
    assert gaps == ()


async def test_a_service_record_nested_too_deep_is_a_gap() -> None:
    zone = Zone().add("amazonses.com", "TXT", "v=spf1 include:l1.example.net -all")
    for depth in range(1, networks.MAX_PUBLISHED_DEPTH + 2):
        zone.add(f"l{depth}.example.net", "TXT", f"v=spf1 include:l{depth + 1}.example.net -all")
    _, gaps = await networks.published_ranges(context(zone))
    (gap,) = [g for g in gaps if g.asked.endswith("Amazon SES")]
    assert (gap.happened, gap.cap) == (networks.TOO_DEEP, networks.MAX_PUBLISHED_DEPTH)
