"""Every gap carries the kind of check it leaves unchecked, set by the source that records it, so
the story can count gaps of one kind together. None is left at the default."""

import ast
from collections.abc import Iterable
from pathlib import Path

import httpx
import pytest
from conftest import CHECKED, Zone
from test_determinism import busy

import sendermap
from sendermap import engine, map_domain
from sendermap.dns import Answer, Status, norm
from sendermap.model import Gap, GapKind, Observed, Run
from sendermap.sources import (
    ct,
    labels,
    mta_sts,
    mx,
    networks,
    reports,
    spf,
    subdomains,
    tokens,
    web,
)

DOMAIN = "mixed.test"
HOME = f'<a href="https://{DOMAIN}/subprocessors">Subprocessors</a>' + "<p>more</p>" * 9


class Failing:
    """The busy zone, where every name it holds no record for fails instead of not existing, so
    every source that asks past what the zone holds gets a failed lookup."""

    def __init__(self, zone: Zone, *, everything: bool = False) -> None:
        self.zone, self.everything = zone, everything

    async def query(self, name: str, rtype: str) -> Answer:
        answer = await self.zone.query(name, rtype)
        if self.everything:
            return Answer(norm(name), rtype, Status.FAILED)
        # No IPv6 address is not a failure, so the web guard lets the homepage be fetched.
        if rtype != "AAAA" and answer.status is not Status.OK and not answer.chain:
            return Answer(norm(name), rtype, Status.FAILED)
        return answer


def pages(request: httpx.Request) -> httpx.Response:
    """The homepage links a subprocessor page that fails; Cert Spotter logs a name too deep, a
    name past the 200 cap and names whose lookups fail; crt.sh fails."""
    host, path = request.url.host, request.url.path
    if host == DOMAIN and path == "/":
        return httpx.Response(200, text=HOME, headers={"content-type": "text/html"})
    if host == "api.certspotter.com":
        names = ["a.b.c.mixed.test", *(f"n{i}.mixed.test" for i in range(3))]
        return httpx.Response(200, json=[{"dns_names": names}])
    return httpx.Response(500)


async def gaps_of(resolver: object, **options: object) -> tuple[Gap, ...]:
    async with httpx.AsyncClient(transport=httpx.MockTransport(pages)) as http:
        result = await map_domain(
            DOMAIN,
            checked_at=CHECKED,
            resolver=resolver,  # type: ignore[arg-type]
            http=http,
            ct_cache=None,
            **options,  # type: ignore[arg-type]
        )
    return result.gaps


async def crashed() -> Observed:
    raise RuntimeError("a source bug")


def crash(*_: object, **__: object) -> object:
    return crashed()


async def test_every_gap_the_engine_records_carries_its_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Low caps, so every cap is reached on the busy domain.
    monkeypatch.setattr(engine, "MAX_SUBDOMAINS", 1)
    monkeypatch.setattr(engine, "SUBDOMAIN_PROBES", 1)
    monkeypatch.setattr(networks, "MAX_RANGES", 1)
    monkeypatch.setattr(spf, "MAX_DEPTH", 1)
    monkeypatch.setattr(subdomains, "MAX_FROM_CT", 1)
    monkeypatch.setattr(ct, "MAX_NAMES", 1)
    monkeypatch.setattr(web, "MAX_BYTES", 80)
    monkeypatch.setattr(ct, "BACKOFF", 0.0)
    zone = busy().public(DOMAIN).add("_mta-sts.mixed.test", "TXT", "v=STSv1; id=1")
    gaps = [
        *await gaps_of(Failing(zone, everything=True), use_ct=True),
        *await gaps_of(Failing(zone), use_ct=True),
        *await gaps_of(Failing(zone), use_web=False),
        *await gaps_of(Failing(zone), use_web=False, use_subdomains=False),
    ]
    for module in (mx, tokens, reports, labels, mta_sts, web, subdomains):
        monkeypatch.setattr(module, "collect" if module is not subdomains else "discover", crash)
    monkeypatch.setattr(ct, "read_logs", crash)
    gaps += await gaps_of(Failing(zone))
    left = [g for g in gaps if g.kind is GapKind.OTHER]
    assert not left, left
    assert {g.kind for g in gaps} == set(GapKind) - {GapKind.OTHER}


def calls_to_gap(paths: Iterable[Path]) -> list[tuple[str, int, ast.Call]]:
    found = []
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Gap":
                found.append((path.name, node.lineno, node))
    return found


def test_every_gap_in_the_package_is_given_a_kind() -> None:
    """The map above reaches every kind; this holds the sites it may not reach."""
    package = Path(sendermap.__file__).parent
    calls = calls_to_gap(package.rglob("*.py"))
    assert len(calls) > 30
    unkinded = [
        (name, line)
        for name, line, call in calls
        if len(call.args) < 3 and not any(k.arg == "kind" for k in call.keywords)
    ]
    assert not unkinded


def test_the_kind_is_additive_in_json() -> None:
    gap = Gap("the website", "not read", GapKind.OFF)
    assert Gap("a", "b").kind is GapKind.OTHER
    assert sendermap.SenderMap("a.test", (), Run(CHECKED, 0.0, 0), gaps=(gap,)).to_dict()[
        "gaps"
    ] == ({"asked": "the website", "happened": "not read", "kind": "off", "count": 0, "cap": 0},)
