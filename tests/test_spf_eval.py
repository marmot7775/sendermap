"""check_host held to the RFC 7208 test suite, every scenario, every case.

`tests/vectors/rfc7208-tests.yml` is the openspf.org suite (release 2014.04) as pyspf ships it
(github.com/sdgathman/pyspf, test/rfc7208-tests.yml at 4bf96ea), under the licence beside it.
Each scenario's zonedata becomes a fake zone: type SPF records are copied to TXT when the name
has no TXT of its own (the suite's rule), `NONE` stands for no record of that type, a type whose
value is `TIMEOUT` fails, and a bare `TIMEOUT` fails every type not listed before it.

Explanations are not compared: exp is read and ignored.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import CHECKED, Zone

from sendermap import catalog
from sendermap.dns import Lookups, Status, norm, parse_doh
from sendermap.sources import Context
from sendermap.sources.spf_eval import Result, Verdict, check_host, mail_from

# Each case the evaluator does not pass, and why. Empty means every case passes.
KNOWN: dict[str, str] = {}

VECTORS = Path(__file__).parent / "vectors" / "rfc7208-tests.yml"
TYPES = frozenset({"A", "AAAA", "MX", "TXT", "PTR", "CNAME", "SPF"})
CATALOG = catalog.load()


@dataclass(frozen=True)
class Case:
    id: str
    scenario: str
    host: str
    mailfrom: str
    helo: str
    results: tuple[str, ...]
    zonedata: dict[str, list[Any]]


def load() -> list[Case]:
    with VECTORS.open(encoding="utf-8") as file:
        scenarios = list(yaml.safe_load_all(file))
    return [
        Case(
            name,
            scenario["description"],
            str(test["host"]),
            str(test["mailfrom"]),
            str(test["helo"]),
            tuple(test["result"]) if isinstance(test["result"], list) else (test["result"],),
            scenario.get("zonedata") or {},
        )
        for scenario in scenarios
        for name, test in scenario["tests"].items()
    ]


def zone_of(zonedata: dict[str, list[Any]]) -> Zone:
    zone = Zone()
    for name, entries in zonedata.items():
        seen: set[str] = set()  # types that answer before a bare TIMEOUT
        spf: list[str] = []
        has_txt = False
        for entry in entries:
            if entry == "TIMEOUT":
                zone.timeouts |= {(norm(name), t) for t in TYPES - seen}
                break
            for rtype, value in entry.items():
                has_txt = has_txt or rtype == "TXT"
                if value == "TIMEOUT":
                    zone.timeouts.add((norm(name), rtype))
                elif value != "NONE":
                    seen.add(rtype)
                    _add(zone, name, rtype, value, spf)
        else:
            if not has_txt:  # the suite's drivers copy SPF to TXT when no TXT is given
                zone.add(name, "TXT", *spf)
    return zone


def _add(zone: Zone, name: str, rtype: str, value: Any, spf: list[str]) -> None:
    if rtype in ("TXT", "SPF"):
        text = "".join(value) if isinstance(value, list) else str(value)
        zone.add(name, rtype, text)
        if rtype == "SPF":
            spf.append(text)
    elif rtype == "MX":
        zone.add(name, "MX", f"{value[0]} {norm(value[1])}")
    elif rtype == "CNAME":
        zone.alias(name, value)
    elif rtype in ("PTR",):
        zone.add(name, rtype, norm(value))
    else:
        zone.add(name, rtype, str(value))


async def run(case: Case) -> Verdict:
    sender, domain = mail_from(case.mailfrom, case.helo)
    ctx = Context(domain, Lookups(zone_of(case.zonedata)), CATALOG, CHECKED)
    return await check_host(ctx, case.host, domain, sender, case.helo)


CASES = load()


def test_every_scenario_is_loaded() -> None:
    assert len({c.scenario for c in CASES}) == 16
    assert len(CASES) == 203
    assert set(KNOWN) <= {c.id for c in CASES}


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(c, marks=pytest.mark.xfail(reason=KNOWN[c.id], strict=True))
        if c.id in KNOWN
        else c
        for c in CASES
    ],
    ids=[c.id for c in CASES],
)
async def test_rfc7208(case: Case) -> None:
    verdict = await run(case)
    assert verdict.result in {Result(r) for r in case.results}, verdict


# ---------------------------------------------------------------- hosted SPF shapes
# Each shape follows the record its vendor publishes for its own domain (October 2026), on the
# fake zone, with documentation addresses: one the record authorizes, one it does not.

KNOWN_IP = "192.0.2.10"
UNKNOWN_IP = "198.51.100.7"


async def verdict(zone: Zone, ip: str, helo: str = "mail.example.com") -> Verdict:
    ctx = Context("example.com", Lookups(zone), CATALOG, CHECKED)
    return await check_host(ctx, ip, "example.com", "news@example.com", helo)


async def test_a_valimail_style_macro_include() -> None:
    # The include is a name built from the address, the HELO name and the domain; the service
    # answers each such name with a record that passes the address or one that does not.
    record = "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email -all"
    known = f"{KNOWN_IP}._ip.mail.example.com._ehlo.example.com._spf.vali.email"
    unknown = f"{UNKNOWN_IP}._ip.mail.example.com._ehlo.example.com._spf.vali.email"
    zone = (
        Zone()
        .add("example.com", "TXT", record)
        .add(known, "TXT", f"v=spf1 ip4:{KNOWN_IP} -all")
        .add(unknown, "TXT", "v=spf1 -all")
    )
    passed = await verdict(zone, KNOWN_IP)
    assert passed.result is Result.PASS
    assert passed.mechanism == f"ip4:{KNOWN_IP}"
    assert passed.record is not None and passed.record.name == known
    assert [e.name for e in passed.path] == [known]
    assert passed.lookups == 1
    failed = await verdict(zone, UNKNOWN_IP)
    assert failed.result is Result.FAIL
    assert failed.mechanism == "-all"
    assert failed.record is not None and failed.record.name == "example.com"


async def test_an_ondmarc_style_exists_record() -> None:
    # The domain includes a name of the service's; that record asks an exists question built
    # from the address, which the service answers with an address only for an authorized one.
    hosted = "_u.example.com._spf.smart.ondmarc.com"
    zone = (
        Zone()
        .add("example.com", "TXT", f"v=spf1 include:{hosted} -all")
        .add(hosted, "TXT", "v=spf1 exists:%{i}._m.example.com._spf.smart.ondmarc.com ~all")
        .add(f"{KNOWN_IP}._m.example.com._spf.smart.ondmarc.com", "A", "127.0.0.2")
    )
    passed = await verdict(zone, KNOWN_IP)
    assert passed.result is Result.PASS
    assert passed.mechanism == "exists:%{i}._m.example.com._spf.smart.ondmarc.com"
    assert [e.name for e in passed.path] == [hosted]
    assert passed.lookups == 2
    failed = await verdict(zone, UNKNOWN_IP)  # softfail inside the include does not match it
    assert failed.result is Result.FAIL
    assert failed.mechanism == "-all"
    assert failed.void_lookups == 1


async def test_an_easydmarc_style_flattened_record() -> None:
    # Two links down, the service's record lists the domain's senders as ranges and names.
    outer = "example_com._es.easydmarc.com"
    flat = "_spf.example_com._d.easydmarc.pro"
    zone = (
        Zone()
        .add("example.com", "TXT", f"v=spf1 include:{outer} -all")
        .add(outer, "TXT", f"v=spf1 include:{flat} ~all")
        .add(flat, "TXT", "v=spf1 ip4:203.0.113.0/24 ip4:192.0.2.0/28 a:out.example.net ~all")
        .add("out.example.net", "A", "203.0.113.200")
    )
    passed = await verdict(zone, KNOWN_IP)
    assert passed.result is Result.PASS
    assert passed.mechanism == "ip4:192.0.2.0/28"
    assert [e.name for e in passed.path] == [outer, flat]
    assert passed.record == passed.path[-1]
    failed = await verdict(zone, UNKNOWN_IP)
    assert failed.result is Result.FAIL
    assert failed.lookups == 3  # two includes and the a term


async def test_a_failed_lookup_is_temperror_naming_the_question() -> None:
    zone = Zone(timeouts={("_spf.example.net", "TXT")}).add(
        "example.com", "TXT", "v=spf1 include:_spf.example.net -all"
    )
    failed = await verdict(zone, KNOWN_IP)
    assert failed.result is Result.TEMPERROR
    assert failed.reason == "lookup failed: _spf.example.net TXT"


async def test_answers_are_read_through_the_maps_cache() -> None:
    zone = (
        Zone().add("example.com", "TXT", "v=spf1 a a mx a -all").add("example.com", "A", KNOWN_IP)
    )
    lookups = Lookups(zone)
    ctx = Context("example.com", lookups, CATALOG, CHECKED)
    await check_host(ctx, UNKNOWN_IP, "example.com", "a@example.com", "mail.example.com")
    assert sorted(zone.asked) == [
        ("example.com", "A"),
        ("example.com", "MX"),
        ("example.com", "TXT"),
    ]
    assert lookups.count == 3


def test_dns_over_https_reads_ptr_records() -> None:
    # The ptr mechanism and the p macro ask PTR, so the DoH resolver must read the type.
    body: dict[str, object] = {
        "Status": 0,
        "Answer": [{"name": "10.2.0.192.in-addr.arpa.", "type": 12, "data": "Mail.Example.com."}],
    }
    answer = parse_doh("10.2.0.192.in-addr.arpa", "PTR", body)
    assert answer.status is Status.OK
    assert answer.records == ("mail.example.com",)
