"""tools/hunt_proofs.py against the fake zone and a fake web: where each kind of pending pattern
is found, which domain's proof wins, what a rerun asks, and the move into vendors.json."""

import asyncio
import importlib.util
import json
import sys
from collections import defaultdict
from importlib import resources
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from conftest import Zone

from sendermap import catalog
from sendermap.dns import Answer

KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
TOOLS = Path(__file__).parent.parent / "tools"
DOMAINS = ("big.test", "small.test", "silent.test")

PENDING: dict[str, Any] = {
    "about": "test",
    "vendors": {
        "Klaviyo": {
            "category": "Marketing",
            "spf_includes": [{"value": "spf.vendor.test"}],
            "dkim_cname": [{"value": "dkim.vendor.test"}],
            "return_path": [{"value": "bounce.vendor.test"}],
            "tracking": [{"value": "track.vendor.test"}],
            "networks": [{"value": "AS64500"}],
            "website": [{"value": "cdn.vendor.test"}],
            "subprocessor_names": [{"value": "Vendor Mail"}],
            "checked": "the vendor's own domains",
            "selectors": [{"shape": {"kind": "fixed", "names": ["vsel"]}}],
        },
        "Partly": {
            "category": "Marketing",
            "mx": [{"value": "mx.partly.test"}],
            "spf_includes": [{"value": "spf.never.test"}],
            "checked": "the vendor's own domains.",
        },
        "Nobody": {
            "category": "Marketing",
            "mx": [{"value": "mx.nowhere.test"}],
            "selectors": [{"shape": {"kind": "fixed", "names": ["bigsel"]}}],
            "checked": "the vendor's own domains.",
        },
    },
}


def load_tool() -> ModuleType:
    sys.path.insert(0, str(TOOLS))  # hunt_proofs imports verify_proofs beside it
    try:
        spec = importlib.util.spec_from_file_location("hunt_proofs", TOOLS / "hunt_proofs.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module  # dataclasses look their module up while it loads
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(TOOLS))


def zone() -> Zone:
    return (
        Zone()
        # big.test, rank 1: the pattern two includes down; a key at every DKIM name.
        .add("big.test", "TXT", "v=spf1 include:_spf.esp.test -all")
        .add("_spf.esp.test", "TXT", "v=spf1 include:spf.vendor.test -all")
        .add("*._domainkey.big.test", "TXT", KEY)
        # small.test, rank 2: everything else.
        .add("small.test", "TXT", "v=spf1 include:spf.vendor.test ~all")
        .add("small.test", "MX", "10 in.mx.partly.test")
        .alias("vsel._domainkey.small.test", "vsel.dkim.vendor.test")
        .add("vsel.dkim.vendor.test", "TXT", KEY)
        # Nobody's name, but Klaviyo hosts the key: proves Klaviyo's CNAME, not Nobody's name.
        .alias("bigsel._domainkey.small.test", "bigsel.dkim.vendor.test")
        .add("bigsel.dkim.vendor.test", "TXT", KEY)
        .alias("bounce.small.test", "b.bounce.vendor.test")
        .alias("click.small.test", "c.bounce.vendor.test")  # a bounce host at a tracking label
        .alias("links.small.test", "l.track.vendor.test")
        .add("mail.small.test", "A", "192.0.2.7")
        .add("7.2.0.192.origin.asn.cymru.com", "TXT", "64500 | 192.0.2.0/24 | US | arin")
    )


def web(request: httpx.Request) -> httpx.Response:
    if request.url.host == "small.test":
        page = '<script src="https://eu.cdn.vendor.test/f.js"></script><p>Vendor Mail</p>'
        return httpx.Response(200, text=page, headers={"content-type": "text/html"})
    if request.url.host == "silent.test":
        raise httpx.ConnectError("refused", request=request)
    return httpx.Response(404)


def files(tmp_path: Path) -> tuple[Path, Path, Path]:
    """The domain list, pending file and vendors.json in tmp_path, written on the first run."""
    domains = tmp_path / "domains.txt"
    pending = tmp_path / "pending.json"
    vendors = tmp_path / "vendors.json"
    if domains.exists():
        return domains, pending, vendors
    domains.write_text("# a test list\n" + "\n".join(DOMAINS) + "\n")
    pending.write_text(json.dumps(PENDING))
    vendors.write_text((resources.files("sendermap") / "data/vendors.json").read_text())
    return domains, pending, vendors


async def run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *argv: str,
    resolver: Any = None,
    handler: Any = web,
) -> tuple[ModuleType, int]:
    tool = load_tool()
    domains, pending, vendors = files(tmp_path)
    monkeypatch.setattr(tool, "PENDING", pending)
    monkeypatch.setattr(tool, "VENDORS", vendors)
    monkeypatch.setattr(tool, "SystemResolver", lambda timeout, nameservers: resolver or zone())
    transport = httpx.MockTransport(handler)
    code = await tool.main([str(domains), "--cache", str(tmp_path / "cache"), *argv], transport)
    return tool, code


async def test_report_names_each_find_and_its_highest_ranked_domain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    await run(monkeypatch, tmp_path, "--parallel", "3")
    out = capsys.readouterr().out
    assert "Proven: 9 of 12 pending patterns" in out
    # Two includes down at rank 1 beats the apex at rank 2; the proof is the include's record.
    assert (
        "  Klaviyo spf_includes spf.vendor.test: esp.test (through big.test), rank 1, "
        "_spf.esp.test (" in out
    )
    assert "_spf.esp.test (" in out and "shown by 2 domains" in out
    # The wildcard under big.test proves nothing, so the key comes from small.test.
    assert "  Klaviyo selectors vsel: small.test, rank 2, vsel._domainkey.small.test (" in out
    assert "  Klaviyo dkim_cname dkim.vendor.test: small.test, rank 2, vsel._domainkey" in out
    # A bounce host only at a bounce label, a tracking host only at a tracking label.
    assert "Klaviyo return_path bounce.vendor.test: small.test, rank 2, bounce.small.test (" in out
    assert "Klaviyo tracking track.vendor.test: small.test, rank 2, links.small.test (" in out
    assert "Klaviyo networks AS64500: small.test, rank 2, mail.small.test (" in out
    assert "Klaviyo website cdn.vendor.test: small.test, rank 2, https://small.test/ (" in out
    assert "Klaviyo subprocessor_names Vendor Mail: small.test, rank 2, https://small" in out
    assert "  Partly mx mx.partly.test: small.test, rank 2, small.test (" in out
    pending = out.split("Still pending: 3 of 12\n", 1)[1]
    assert pending.startswith(
        "  Partly spf_includes spf.never.test\n"
        "  Nobody mx mx.nowhere.test\n"
        # big.test's wildcard answers it, and small.test's key is Klaviyo's: neither proves it.
        "  Nobody selectors bigsel\n"
    )
    assert "Domains that answered nothing at all: 1\n  silent.test\n" in out
    assert out.rstrip().endswith("9 proven, 3 still pending, 1 domain answered nothing")


async def test_a_rerun_asks_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    await run(monkeypatch, tmp_path)
    first = capsys.readouterr().out
    again, fetched = zone(), []

    def counting(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        return web(request)

    await run(monkeypatch, tmp_path, "--parallel", "2", resolver=again, handler=counting)
    assert capsys.readouterr().out == first
    assert again.asked == []
    assert fetched == ["https://silent.test/"]  # a request that raised is asked again


class Watch:
    """The zone, slowed down, counting the queries in flight under each hunted domain."""

    def __init__(self) -> None:
        self.zone = zone()
        self.name = self.zone.name
        self.now: defaultdict[str, int] = defaultdict(int)
        self.most: defaultdict[str, int] = defaultdict(int)
        self.overall = self.peak = 0

    async def query(self, name: str, rtype: str) -> Answer:
        owner = next((d for d in DOMAINS if name == d or name.endswith("." + d)), name)
        self.now[owner] += 1
        self.overall += 1
        self.most[owner] = max(self.most[owner], self.now[owner])
        self.peak = max(self.peak, self.overall)
        await asyncio.sleep(0.001)
        self.now[owner] -= 1
        self.overall -= 1
        return await self.zone.query(name, rtype)


async def test_domains_run_in_parallel_their_queries_never_do(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    watch = Watch()
    await run(monkeypatch, tmp_path, "--parallel", "3", resolver=watch)
    capsys.readouterr()
    assert all(watch.most[d] == 1 for d in DOMAINS)
    assert watch.peak > 1


async def test_move_takes_proven_patterns_with_their_proofs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    await run(monkeypatch, tmp_path)
    tool, code = await run(monkeypatch, tmp_path, "--move", "--parallel", "3")
    capsys.readouterr()
    assert code == 0
    pending = json.loads((tmp_path / "pending.json").read_text())["vendors"]
    vendors = json.loads((tmp_path / "vendors.json").read_text())
    loaded = catalog.build(vendors)  # every moved proof passes the loader's checks
    # Klaviyo moved whole; Partly keeps what is still unproven; Nobody stays as it was.
    assert list(pending) == ["Partly", "Nobody"]
    assert pending["Partly"]["spf_includes"] == [{"value": "spf.never.test"}]
    assert "mx" not in pending["Partly"]
    assert pending["Nobody"]["checked"].startswith("the vendor's own domains. ")
    assert "the 3 domains in data/hunt_domains.txt" in pending["Nobody"]["checked"]
    assert vendors["vendors"]["Partly"] == {
        "category": "Marketing",
        "mx": [
            {
                "value": "mx.partly.test",
                "proof": {"domain": "small.test", "record": "small.test", "date": tool_day(tool)},
            }
        ],
    }
    klaviyo = vendors["vendors"]["Klaviyo"]
    assert klaviyo["spf_includes"][-1]["proof"]["record"] == "_spf.esp.test"
    assert klaviyo["selectors"][-1] == {
        "shape": {"kind": "fixed", "names": ["vsel"]},
        "source": "pattern",
        "reference": None,
        "proof": {
            "domain": "small.test",
            "record": "vsel._domainkey.small.test",
            "date": tool_day(tool),
        },
    }
    assert loaded.mx("in.mx.partly.test") == "Partly"
    assert "vsel" in loaded.probe_selectors
    names = list(vendors["vendors"])
    assert names == sorted(names, key=str.casefold)


def tool_day(tool: ModuleType) -> str:
    return str(tool.date.today().isoformat())
