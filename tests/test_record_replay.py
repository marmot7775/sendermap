"""Record and replay: what a recorder keeps, a replayer gives back, and nothing else."""

import json
from pathlib import Path

import httpx
import pytest
from conftest import CHECKED, Zone
from test_determinism import busy

from sendermap import map_domain
from sendermap.dns import Answer, Status
from sendermap.testing import (
    Case,
    RecordingResolver,
    RecordingTransport,
    ReplayResolver,
    ReplayTransport,
    UnrecordedError,
    comparable,
    replay,
)


async def test_a_replayed_answer_is_the_recorded_one(tmp_path: Path) -> None:
    zone = (
        Zone(failing={"broken.test"}).add("b.test", "TXT", "v=spf1 -all").alias("a.test", "b.test")
    )
    recorder = RecordingResolver(zone)
    asked = [("b.test", "TXT"), ("a.test", "TXT"), ("broken.test", "MX"), ("gone.test", "A")]
    live = [await recorder.query(name, rtype) for name, rtype in asked]
    recorder.save(tmp_path / "dns.json")

    replayer = ReplayResolver(tmp_path / "dns.json", "fake zone")
    assert [await replayer.query(name, rtype) for name, rtype in asked] == live
    assert live[1] == Answer("a.test", "TXT", Status.OK, ("v=spf1 -all",), ("b.test",))
    assert live[2].status is Status.FAILED  # could not check replays as could not check
    assert live[3].status is Status.NXDOMAIN


async def test_the_file_is_sorted_one_object_per_question(tmp_path: Path) -> None:
    recorder = RecordingResolver(Zone().add("b.test", "TXT", "x").add("a.test", "MX", "10 m.test"))
    for name, rtype in (("b.test", "TXT"), ("a.test", "MX"), ("a.test", "A")):
        await recorder.query(name, rtype)
    recorder.save(tmp_path / "dns.json")
    lines = (tmp_path / "dns.json").read_text().splitlines()
    rows = [json.loads(line.rstrip(",")) for line in lines[1:-1]]
    assert [(r["name"], r["rtype"]) for r in rows] == [
        ("a.test", "A"),
        ("a.test", "MX"),
        ("b.test", "TXT"),
    ]


async def test_an_unrecorded_question_raises_and_is_named(tmp_path: Path) -> None:
    RecordingResolver(Zone()).save(tmp_path / "dns.json")
    replayer = ReplayResolver(tmp_path / "dns.json", "fake zone")
    with pytest.raises(UnrecordedError, match=r"TXT new\.test"):
        await replayer.query("New.Test.", "txt")
    assert replayer.missed == [("new.test", "TXT")]


def site(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/old":
        return httpx.Response(301, headers={"location": "/new"})
    if request.url.path == "/down":
        raise httpx.ConnectTimeout("timed out", request=request)
    return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, html="é")


async def test_a_replayed_page_is_the_recorded_one(tmp_path: Path) -> None:
    recorder = RecordingTransport(httpx.MockTransport(site))
    async with httpx.AsyncClient(transport=recorder) as client:
        moved = await client.get("https://a.test/old")
        page = await client.get("https://a.test/new")
        with pytest.raises(httpx.ConnectTimeout):
            await client.get("https://a.test/down")
    recorder.save(tmp_path / "http.json")

    replayer = ReplayTransport(tmp_path / "http.json")
    async with httpx.AsyncClient(transport=replayer) as client:
        again = await client.get("https://a.test/old")
        assert (again.status_code, again.headers["location"]) == (301, "/new")
        assert (moved.status_code, moved.headers["location"]) == (301, "/new")
        again = await client.get("https://a.test/new")
        assert (again.status_code, again.text) == (page.status_code, page.text) == (200, "é")
        assert again.headers["content-type"] == "text/html; charset=utf-8"
        with pytest.raises(httpx.ConnectTimeout):
            await client.get("https://a.test/down")
        with pytest.raises(UnrecordedError, match=r"GET https://a\.test/elsewhere"):
            await client.get("https://a.test/elsewhere")
    assert replayer.missed == [("GET", "https://a.test/elsewhere")]


async def test_a_recorded_map_replays_to_the_same_map(tmp_path: Path) -> None:
    zone = busy().public("mixed.test", "www.mixed.test")

    def pages(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.certspotter.com":
            return httpx.Response(200, json=[{"dns_names": ["news.mixed.test"]}])
        if request.url.host == "mixed.test":
            return httpx.Response(301, headers={"location": "https://www.mixed.test/"})
        html = '<script src="https://static.klaviyo.com/onsite/js/klaviyo.js"></script>'
        return httpx.Response(200, headers={"content-type": "text/html"}, html=html)

    resolver = RecordingResolver(zone)
    transport = RecordingTransport(httpx.MockTransport(pages))
    case = Case("mixed.test", CHECKED, use_web=True, use_subdomains=True, resolver=zone.name)
    async with httpx.AsyncClient(transport=transport) as http:
        live = await map_domain(case.domain, checked_at=CHECKED, resolver=resolver, http=http)
    resolver.save(tmp_path / "dns.json")
    transport.save(tmp_path / "http.json")
    (tmp_path / "case.json").write_text(json.dumps(case.to_dict()))

    replayed = await replay(tmp_path)
    assert replayed.missed == []
    assert replayed.map == live
    assert comparable(replayed.map) == comparable(live)
    assert "elapsed" not in comparable(live)["run"]
    assert "lookups" not in comparable(live)["run"]
    assert len(transport.responses) == 3  # the certificate log, the redirect, the page


async def test_a_new_question_is_missed_not_answered(tmp_path: Path) -> None:
    """A code path the recording never saw fails loudly, even behind the engine's guards."""
    resolver = RecordingResolver(busy())
    await map_domain(
        "mixed.test", checked_at=CHECKED, resolver=resolver, use_web=False, use_subdomains=False
    )
    del resolver.answers[("_dmarc.mixed.test", "TXT")]
    resolver.save(tmp_path / "dns.json")
    case = Case("mixed.test", CHECKED, use_web=False, use_subdomains=False, resolver=resolver.name)
    (tmp_path / "case.json").write_text(json.dumps(case.to_dict()))
    replayed = await replay(tmp_path)
    assert replayed.missed == ["TXT _dmarc.mixed.test"]
