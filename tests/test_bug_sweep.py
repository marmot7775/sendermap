"""Bugs found in the 2026-11 sweep, each pinned by the smallest case that showed it."""

import importlib
import re
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from conftest import Zone, context

from sendermap import cli, map_domain
from sendermap.model import SenderMap, Severity
from sendermap.sources import reports, spf

OFFLINE = ["--no-web", "--no-subdomains"]


async def titles(zone: Zone) -> list[str]:
    observed, _ = await spf.collect(context(zone), "example.com")
    return [f.title for f in observed.findings]


# ---------------------------------------------------------------- SPF


@pytest.mark.parametrize("record", ["v=spf1 all", "v=spf1 +all", "v=spf1 a +all"])
async def test_all_without_a_qualifier_is_plus_all(record: str) -> None:
    # RFC 7208 section 4.6.2: a term with no qualifier is "+", so "all" passes every server.
    zone = Zone().add("example.com", "TXT", record)
    assert "SPF at example.com authorizes every server" in await titles(zone)


@pytest.mark.parametrize(
    "record", ["v=spf1 -all", "v=spf1 ~all", "v=spf1 ?all", "v=spf1 -all +all"]
)
async def test_a_qualified_all_other_than_plus_is_not_flagged(record: str) -> None:
    zone = Zone().add("example.com", "TXT", record)
    assert "SPF at example.com authorizes every server" not in await titles(zone)


# ---------------------------------------------------------------- DMARC reports

AUTHORIZED = "example.com._report._dmarc.r.example.net"  # r.example.net takes the reports


async def report_hosts(zone: Zone) -> list[str]:
    observed = await reports.collect(context(zone))
    return [u.value for u in observed.unknowns] + [c.service for c in observed.claims]


async def test_two_dmarc_records_are_no_dmarc_record() -> None:
    # RFC 9989 section 4.10 (and RFC 7489 section 6.6.3): more than one record and a receiver
    # applies none of them, so neither sends it a report.
    zone = (
        Zone()
        .add("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:a@one.example.net")
        .add("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:a@two.example.net")
    )
    assert await report_hosts(zone) == []
    observed = await reports.collect(context(zone))
    (finding,) = observed.findings
    assert finding.severity is Severity.RISK
    assert finding.title == "_dmarc.example.com publishes 2 DMARC records"


async def test_two_tls_rpt_records_are_no_policy() -> None:
    zone = (
        Zone()
        .add("_smtp._tls.example.com", "TXT", "v=TLSRPTv1; rua=mailto:a@one.example.net")
        .add("_smtp._tls.example.com", "TXT", "v=TLSRPTv1; rua=mailto:a@two.example.net")
    )
    assert await report_hosts(zone) == []
    (finding,) = (await reports.collect(context(zone))).findings
    assert finding.title == "_smtp._tls.example.com publishes 2 TLS-RPT records"


@pytest.mark.parametrize("version", ["v=DMARC10", "v=DMARC1x", "v=DMARC2"])
async def test_only_version_dmarc1_is_a_dmarc_record(version: str) -> None:
    zone = Zone().add("_dmarc.example.com", "TXT", f"{version}; p=none; rua=mailto:a@r.example.net")
    assert await report_hosts(zone) == []


async def test_a_dmarc_record_with_spaces_around_the_version_still_reads() -> None:
    zone = (
        Zone()
        .add("_dmarc.example.com", "TXT", "v = DMARC1 ; p=none; rua=mailto:a@r.example.net")
        .add(AUTHORIZED, "TXT", "v=DMARC1;")
    )
    assert await report_hosts(zone) == ["r.example.net"]


async def test_a_non_dmarc_txt_beside_one_dmarc_record_is_not_a_second_record() -> None:
    zone = (
        Zone()
        .add("_dmarc.example.com", "TXT", "some note")
        .add("_dmarc.example.com", "TXT", "v=DMARC1; p=none; rua=mailto:a@r.example.net")
        .add(AUTHORIZED, "TXT", "v=DMARC1;")
    )
    assert await report_hosts(zone) == ["r.example.net"]


# ---------------------------------------------------------------- the command line


def test_a_claimed_file_that_is_not_text_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "SystemResolver", Zone)
    claimed = tmp_path / "claimed.bin"
    claimed.write_bytes(b"\xff\xfe\x00Mailchimp")
    assert cli.main(["example.test", "--claimed-file", str(claimed), *OFFLINE]) == cli.BAD_INPUT
    assert "cannot read" in capsys.readouterr().err


# ---------------------------------------------------------------- the website


@pytest.fixture
def dead_resolver_site(monkeypatch: pytest.MonkeyPatch) -> Iterator[ModuleType]:
    """The website with every lookup of down.test failing, and its state emptied around the test."""
    pytest.importorskip("fastapi")
    site = importlib.import_module("sendermap.web.app")
    dead = Zone(failing={"down.test"})

    async def build(domain: str, **kwargs: Any) -> SenderMap:
        kwargs.pop("http", None)
        return await map_domain(
            domain, resolver=dead, use_web=False, use_subdomains=False, **kwargs
        )

    monkeypatch.setattr(site, "map_domain", build)
    for held in (site.state.cache, site.state.running, site.state.seen, site.state.built):
        held.clear()
    yield site
    for held in (site.state.cache, site.state.running, site.state.seen, site.state.built):
        held.clear()


async def test_a_map_of_unreadable_records_is_an_error_and_is_not_kept(
    dead_resolver_site: ModuleType,
) -> None:
    # The command line exits 3 and the MCP tool errors when the domain's own records could not
    # be read. The API answers the same way, and does not cache what a resolver outage gave.
    site = dead_resolver_site
    transport = httpx.ASGITransport(app=site.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://site.test") as client:
        for path in ("/api/map", "/api/map.md", "/api/map.html"):
            reply = await client.get(path, params={"d": "down.test"})
            assert reply.status_code == 503, path
            assert "could not be read" in reply.json()["detail"]
    assert site.state.cache == {}


# ---------------------------------------------------------------- published ranges


async def test_a_range_after_all_in_a_services_record_is_not_published() -> None:
    # Receivers stop at the first "all" (RFC 7208, section 4.6), so a term after it publishes
    # nothing the service's customers can send from.
    from sendermap.sources import networks  # noqa: PLC0415

    zone = Zone().add("sendgrid.net", "TXT", "v=spf1 ip4:192.0.2.0/24 -all ip4:198.51.100.0/24")
    published, _ = await networks.published_ranges(context(zone))
    held = {str(n) for n in published}
    assert "192.0.2.0/24" in held
    assert "198.51.100.0/24" not in held


# ---------------------------------------------------------------- docs


def test_the_readme_carries_no_release_number() -> None:
    # The version lives in the git tag and server.json; a copy in the README went stale.
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    assert not re.search(r"early release \(\d", readme)


def test_the_readme_and_the_page_say_what_makes_a_service_likely() -> None:
    root = Path(__file__).parent.parent
    for text in (
        (root / "README.md").read_text(encoding="utf-8"),
        (root / "sendermap/web/static/index.html").read_text(encoding="utf-8"),
    ):
        flat = " ".join(text.split())
        assert "subprocessor listing" in flat


async def test_the_stream_says_why_a_map_was_refused(dead_resolver_site: ModuleType) -> None:
    # /api/map answers a busy domain with its reason (429); the stream said only "could not be
    # built", and said nothing of an unreadable domain either.
    site = dead_resolver_site
    transport = httpx.ASGITransport(app=site.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://site.test") as client:
        down = await client.get("/api/map/stream", params={"d": "down.test"})
        assert "could not be read" in down.text
        site.state.built["busy.test"] = [time.monotonic()] * site.DOMAIN_BUILDS_PER_MINUTE
        busy = await client.get("/api/map/stream", params={"d": "busy.test"})
        assert "mapped too often" in busy.text
