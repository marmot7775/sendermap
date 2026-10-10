"""Rule 3: every cap that leaves names unasked records a gap naming the cap and the count."""

import ipaddress

import httpx
import pytest
from conftest import CHECKED, Zone, context

from sendermap import engine, map_domain
from sendermap.model import Evidence, Kind, Observed, SenderMap
from sendermap.sources import Context, networks, spf, subdomains, web


def ev(value: str) -> Evidence:
    return Evidence("example.com", "TXT", value, CHECKED)


def asked(observed: Observed | SenderMap) -> dict[str, str]:
    return {g.asked: g.happened for g in observed.gaps}


async def test_sending_subdomains_past_the_cap_are_a_gap(
    offline: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine, "MAX_SUBDOMAINS", 1)
    zone = (
        Zone()
        .add("email.acme.test", "TXT", "v=spf1 include:mailgun.org ~all")
        .add("mail.acme.test", "TXT", "v=spf1 include:sendgrid.net ~all")
    )
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    assert result.subdomains_checked == ("email.acme.test",)
    assert asked(result)["sending subdomains"].startswith("1 of 2 not checked")


async def test_dkim_names_left_out_of_a_subdomains_budget_are_a_gap(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("email.acme.test", "TXT", "v=spf1 include:mailgun.org ~all")
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    happened = asked(result)["DKIM selectors at email.acme.test"]
    assert "not asked" in happened and f"first {engine.SUBDOMAIN_PROBES}" in happened


async def test_ranges_past_the_cap_are_a_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(networks, "MAX_RANGES", 1)
    ranges = [("198.51.100.0/24", ev("ip4:198.51.100.0/24")), ("203.0.113.0/24", ev("ip4:x"))]
    observed = await networks.collect(context(Zone()), "example.com", ranges)
    assert len(observed.unknowns) == 1
    assert asked(observed)["network owners of the IP ranges in SPF at example.com"] == (
        "1 of 2 not looked up: only the first 1 were (cap)"
    )


async def test_certificate_log_names_too_deep_or_past_the_cap_are_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subdomains, "MAX_FROM_CT", 2)
    logged = ["a.example.com", "b.example.com", "c.example.com", "x.y.z.example.com"]

    def log(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"dns_names": logged}])

    async with httpx.AsyncClient(transport=httpx.MockTransport(log)) as http:
        ctx = context(Zone())
        ctx = Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http)
        found = await subdomains.discover(ctx)
    gaps = {g.asked: g.happened for g in found.gaps}
    assert gaps["certificate log names more than 2 labels deep"].startswith("1 not asked")
    assert gaps["certificate log names"].startswith("1 of 3 not asked")


async def test_spf_includes_past_the_depth_cap_are_a_gap() -> None:
    zone = Zone().add("example.com", "TXT", "v=spf1 include:l1.example.net -all")
    for level in range(1, spf.MAX_DEPTH + 2):
        zone.add(f"l{level}.example.net", "TXT", f"v=spf1 include:l{level + 1}.example.net -all")
    observed, _ = await spf.collect(context(zone), "example.com")
    (gap,) = observed.gaps
    assert gap.asked.endswith(f"l{spf.MAX_DEPTH + 1}.example.net")
    assert gap.happened == f"1 not walked (cap of {spf.MAX_DEPTH} levels)"


async def test_a_page_cut_at_the_size_cap_is_a_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web, "MAX_BYTES", 10)

    def page(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<p>" + "x" * 50, headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(page)) as http:
        ctx = context(Zone())
        ctx = Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http)
        observed = await web.collect(ctx)
    assert asked(observed)["the website: GET https://example.com/"].startswith(
        "only the first 10 bytes"
    )


def origin6(zone: Zone, address: str, asn: str, name: str) -> Zone:
    nibbles = ".".join(reversed(ipaddress.IPv6Address(address).exploded.replace(":", "")))
    zone.add(f"{nibbles}.origin6.asn.cymru.com", "TXT", f"{asn[2:]} | {address}/32 | US | arin")
    zone.add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005-01-01 | {name}")
    return zone


async def test_an_ipv6_range_inside_a_services_published_range_is_that_service() -> None:
    zone = Zone().add("_spf.google.com", "TXT", "v=spf1 ip6:2001:4860:4000::/36 ~all")
    observed = await networks.collect(
        context(zone), "example.com", [("2001:4860:4864::/56", ev("ip6:2001:4860:4864::/56"))]
    )
    assert [(c.service, c.kind) for c in observed.claims] == [
        ("Google Workspace", Kind.SPF_NETWORK)
    ]


async def test_an_ipv6_range_is_named_by_its_network_or_listed_as_unknown() -> None:
    zone = origin6(Zone(), "2600:1f18::1", "AS14618", "AMAZON-AES - Amazon.com, Inc., US")
    observed = await networks.collect(
        context(zone),
        "example.com",
        [("2600:1f18::1", ev("ip6:2600:1f18::1")), ("2001:db8::/32", ev("ip6:2001:db8::/32"))],
    )
    assert observed.claims == ()
    assert [(u.what, u.value) for u in observed.unknowns] == [
        ("IP address in SPF", "2600:1f18::1 (AS14618, Amazon Web Services)"),
        ("IP range in SPF", "2001:db8::/32 (no one network announces it)"),
    ]


async def test_the_spf_walk_carries_ipv6_ranges_to_the_networks_source() -> None:
    zone = Zone().add("example.com", "TXT", "v=spf1 ip6:2001:db8::/32 ip4:192.0.2.0/24 -all")
    _, tree = await spf.collect(context(zone), "example.com")
    assert [cidr for cidr, _ in tree.ranges] == ["2001:db8::/32", "192.0.2.0/24"]
