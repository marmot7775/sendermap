"""Rules 5 and 7: one proofed list of vendor selectors credits keys, backs generic names and makes
the probe sweep, and the vendor file is read once."""

import json
import sys
from importlib import resources

import httpx
from conftest import CHECKED, Zone

from sendermap import catalog, map_domain
from sendermap.selectors import build_dictionary

SHIPPED = json.loads(resources.files("sendermap").joinpath("data/vendors.json").read_text())
PENDING = json.loads(resources.files("sendermap").joinpath("data/vendors_pending.json").read_text())
listening: list[list[str]] = []


def _audit(event: str, args: tuple[object, ...]) -> None:
    if event == "open" and listening:
        listening[-1].append(str(args[0]))


sys.addaudithook(_audit)


def test_the_file_keeps_one_selector_list() -> None:
    assert not [v for v, block in SHIPPED["vendors"].items() if "dkim_selectors" in block]
    assert "probe_selectors" not in SHIPPED["rules"]


def test_names_credited_backed_and_probed_all_come_from_the_proofed_rules() -> None:
    loaded = catalog.load()
    proofed = set(build_dictionary(loaded.rules))
    assert set(loaded.selectors) == proofed
    assert all(loaded.selectors_of(s) <= proofed for s in loaded.services)
    assert set(loaded.probe_selectors) == proofed | loaded.generic_selectors
    assert len(loaded.probe_selectors) == len(set(loaded.probe_selectors))


def test_a_pending_selector_is_neither_probed_nor_credited() -> None:
    loaded = catalog.load()
    pending = {
        name
        for block in PENDING["vendors"].values()
        for entry in block.get("selectors", ())
        for name in entry["shape"]["names"]
    }
    assert pending
    for name in pending - set(loaded.selectors):
        assert name not in loaded.probe_selectors or name in loaded.generic_selectors, name
        assert loaded.dkim_key(name, (), backed=None) is None, name


async def test_the_vendor_file_is_read_once_for_a_map(offline: httpx.AsyncClient) -> None:
    catalog.load.cache_clear()
    opened: list[str] = []
    listening.append(opened)
    try:
        await map_domain("example.com", checked_at=CHECKED, resolver=Zone(), http=offline)
        await map_domain("example.org", checked_at=CHECKED, resolver=Zone(), http=offline)
    finally:
        listening.clear()
    assert len([p for p in opened if p.endswith("vendors.json")]) == 1
