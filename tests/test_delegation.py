"""A sending subdomain delegated by NS to a service's nameservers, as Klaviyo's recommended setup
asks for send.example.com: the delegation is the service's claim there, the subdomain is checked
like any other sending subdomain, and NS anywhere else credits nobody."""

import copy
import json
from importlib import resources
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone, context
from test_verify_proofs import load_tool

from sendermap import catalog, map_domain
from sendermap.model import Evidence, Kind, Tier
from sendermap.sources import subdomains

KLAVIYO_NS = ("ns1.klaviyo.com", "ns2.klaviyo.com", "ns3.klaviyo.com", "ns4.klaviyo.com")
SHIPPED: dict[str, Any] = json.loads(
    resources.files("sendermap").joinpath("data/vendors.json").read_text()
)
PROOF = {"domain": "vendor.test", "record": "send.vendor.test", "date": "2026-10-11"}


def with_delegation(entry: object) -> dict[str, Any]:
    raw: dict[str, Any] = copy.deepcopy(SHIPPED)
    raw["vendors"]["Test Vendor"] = {"category": "Marketing", "delegation_ns": [entry]}
    return raw


def test_a_delegation_pattern_loads_with_its_proof_and_names_the_nameserver() -> None:
    built = catalog.build(with_delegation({"value": "dns.vendor.net", "proof": PROOF}))
    assert built.delegation("NS1.dns.vendor.net.") == "Test Vendor"
    assert built.delegation("dns.vendor.net.evil.example") is None
    assert catalog.load().delegation("ns3.klaviyo.com") == "Klaviyo"


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"value": "dns.vendor.net"}, "no proof"),
        ({"value": "dns.vendor.net", "proof": {**PROOF, "record": "vendor.test"}}, "a name under"),
        ({"value": "dns.vendor.net", "proof": {**PROOF, "record": "send.other.test"}}, "a name"),
    ],
)
def test_a_delegation_without_a_proof_under_its_domain_is_refused(
    entry: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        catalog.build(with_delegation(entry))


async def test_a_delegated_label_is_the_services_claim_and_a_sending_subdomain(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("send.acme.test", "NS", *KLAVIYO_NS)
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    (klaviyo,) = [s for s in result.services if s.name == "Klaviyo"]
    assert klaviyo.tier is Tier.CONFIGURED
    (claim,) = klaviyo.claims
    assert claim.kind is Kind.DELEGATION and claim.where == "send.acme.test"
    assert claim.evidence == Evidence("send.acme.test", "NS", "ns1.klaviyo.com", CHECKED)
    assert result.subdomains_checked == ("send.acme.test",)
    # The delegation backs Klaviyo's selector names under it, as an SPF or MX claim would.
    assert ("kl._domainkey.send.acme.test", "TXT") in zone.asked


async def test_a_label_delegated_to_nameservers_no_service_is_known_by_asks_nothing_more(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("send.acme.test", "NS", "ns-1.awsdns-01.com", "ns-2.awsdns-02.net")
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    assert result.services == () and result.subdomains_checked == ()
    assert not [name for name, _ in zone.asked if name.endswith("_domainkey.send.acme.test")]


async def test_ns_reached_through_a_cname_delegates_nothing() -> None:
    zone = (
        Zone()
        .alias("send.example.com", "u1.wl1.vendor.example")
        .add("u1.wl1.vendor.example", "NS", *KLAVIYO_NS)
    )
    found = await subdomains.discover(context(zone), ())
    assert found.delegations == () and "send.example.com" not in found.sending


async def test_a_failed_lookup_names_ns_among_the_questions() -> None:
    found = await subdomains.discover(context(Zone(failing={"send.example.com"})), ())
    (gap,) = found.gaps
    assert gap.asked == "sending subdomains: TXT, MX and NS at send.example.com"


async def test_verify_proofs_finds_a_delegation_only_at_the_name_itself() -> None:
    tool = load_tool()
    dns = (
        Zone()
        .add("send.vendor.test", "NS", *KLAVIYO_NS)
        .alias("send.alias.test", "send.vendor.test")
        .add("send.other.test", "NS", "ns-1.awsdns-01.com")
    )
    async with httpx.AsyncClient() as http:
        checker = tool.Checker(dns, http)
        seen = await tool.CHECKS["delegation_ns"](checker, "send.vendor.test", "klaviyo.com")
        assert seen.shows and seen.observed == " | ".join(KLAVIYO_NS)
        through = await tool.CHECKS["delegation_ns"](checker, "send.alias.test", "klaviyo.com")
        assert not through.shows and through.answered
        other = await tool.CHECKS["delegation_ns"](checker, "send.other.test", "klaviyo.com")
        assert not other.shows


@pytest.mark.parametrize(
    ("nameserver", "vendor"),
    [
        ("ns1.emarsys.net", "Emarsys"),
        ("ns1.shortest-route.com", "Mapp"),
        ("ns1.ecircle.de", "Mapp"),
        ("ns1.crdl.io", "Cordial"),
        ("ns0.dns.dotdigital.com", "Dotdigital"),
        ("ns0.dns.dotmailer.co.uk", "Dotdigital"),
        ("gns194a.sendsay.ru", "Sendsay"),
    ],
)
async def test_each_delegating_esp_is_credited_by_its_nameservers(
    offline: httpx.AsyncClient, nameserver: str, vendor: str
) -> None:
    zone = Zone().add("email.acme.test", "NS", nameserver)
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    (service,) = result.services
    assert service.name == vendor and service.tier is Tier.CONFIGURED
    assert [c.kind for c in service.claims] == [Kind.DELEGATION]


def test_cordials_mx_inside_sparkpost_is_cordials_by_the_longest_pattern() -> None:
    assert catalog.load().mx("cordial.mx.e.sparkpost.com") == "Cordial"
    assert catalog.load().mx("other.mx.e.sparkpost.com") != "Cordial"
