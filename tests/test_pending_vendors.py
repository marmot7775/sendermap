"""Vendor patterns without proofs wait in data/vendors_pending.json, which the engine never reads.
A record that only a pending pattern would have matched is reported as not recognised, with its
hostname."""

import json
import sys
from importlib import resources
from pathlib import Path

import httpx
import pytest
from conftest import CHECKED, Zone

from sendermap import catalog, map_domain

PENDING_FILE = Path(str(resources.files("sendermap").joinpath("data/vendors_pending.json")))
PENDING = json.loads(PENDING_FILE.read_text())["vendors"]
KEY = "v=DKIM1; k=rsa; p=" + "A" * 392
# Files opened while a test listens. An audit hook cannot be removed, so it stays installed and
# records only while `listening` holds a list.
listening: list[list[str]] = []


def _audit(event: str, args: tuple[object, ...]) -> None:
    if event == "open" and listening:
        listening[-1].append(str(args[0]))


sys.addaudithook(_audit)


async def test_the_engine_never_opens_the_pending_file(offline: httpx.AsyncClient) -> None:
    catalog.load.cache_clear()
    opened: list[str] = []
    listening.append(opened)
    try:
        catalog.load()
        await map_domain("example.com", checked_at=CHECKED, resolver=Zone(), http=offline)
    finally:
        listening.clear()
    assert any(p.endswith("vendors.json") for p in opened)  # the hook sees the data files
    assert not [p for p in opened if "vendors_pending" in p]


def _uncovered(field: str) -> list[tuple[str, str]]:
    """(vendor, host) for each pending host pattern no proven pattern also matches. A label
    CNAME is matched against both the bounce and the tracking table, as the labels source does."""
    loaded = catalog.load()
    label = {"return_path": "bounce", "tracking": "links"}.get(field)

    def covered(host: str) -> bool:
        if label:
            return loaded.label_cname(label, f"x.{host}") is not None
        return loaded.tables[field].match(f"x.{host}") is not None

    return [
        (vendor, entry["value"])
        for vendor, block in PENDING.items()
        for entry in block.get(field, ())
        if not covered(entry["value"])
    ]


def _zone(field: str, host: str) -> Zone:
    zone = Zone()
    match field:
        case "spf_includes":
            zone.add("example.com", "TXT", f"v=spf1 include:{host} -all")
        case "mx":
            zone.add("example.com", "MX", f"10 {host}")
        case "dkim_cname":
            zone.alias("default._domainkey.example.com", f"key.{host}").add(
                f"key.{host}", "TXT", KEY
            )
        case "return_path":
            zone.alias("bounce.example.com", f"x.{host}")
        case "tracking":
            zone.alias("links.example.com", f"x.{host}")
        case "reporting":
            zone.add("_dmarc.example.com", "TXT", f"v=DMARC1; p=none; rua=mailto:r@{host}")
    return zone


CASES = [
    pytest.param(field, vendor, host, id=f"{field}-{host}")
    for field in ("spf_includes", "mx", "dkim_cname", "return_path", "tracking", "reporting")
    for vendor, host in _uncovered(field)
]


@pytest.mark.parametrize(("field", "vendor", "host"), CASES)
async def test_a_host_only_a_pending_pattern_matches_is_unknown_with_its_hostname(
    offline: httpx.AsyncClient, field: str, vendor: str, host: str
) -> None:
    result = await map_domain(
        "example.com",
        checked_at=CHECKED,
        resolver=_zone(field, host),
        http=offline,
        use_web=False,
        use_subdomains=False,
    )
    assert vendor not in {s.name for s in result.services}
    assert [u for u in result.unknowns if host in u.value], result.unknowns


async def test_an_address_in_a_pending_network_is_unknown_with_its_network(
    offline: httpx.AsyncClient,
) -> None:
    (vendor, asn), *_ = [
        (vendor, entry["value"])
        for vendor, block in PENDING.items()
        for entry in block.get("networks", ())
    ]
    zone = (
        Zone()
        .add("example.com", "TXT", "v=spf1 ip4:192.0.2.1 -all")
        .add("1.2.0.192.origin.asn.cymru.com", "TXT", f"{asn[2:]} | 192.0.2.0/24 | US | arin")
        .add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005 | {vendor.upper()}")
    )
    result = await map_domain(
        "example.com",
        checked_at=CHECKED,
        resolver=zone,
        http=offline,
        use_web=False,
        use_subdomains=False,
    )
    assert vendor not in {s.name for s in result.services}
    assert [u for u in result.unknowns if asn in u.value], result.unknowns


def test_every_pending_block_says_what_was_checked() -> None:
    assert PENDING
    for vendor, block in PENDING.items():
        assert block.get("checked", "").strip(), vendor
        assert vendor not in catalog.load().services or set(block) - {"category", "checked"}
