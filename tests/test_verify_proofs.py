"""tools/verify_proofs.py against the fake zone and a fake web: what each kind of proof needs,
the --json shape, and what fails the run."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import httpx
import pytest
from conftest import Zone

from sendermap.catalog import Pattern
from sendermap.proofs import Proof
from sendermap.selectors import Fixed, Rule, Source

KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
FIELDS = ["vendor", "field", "pattern", "domain", "record", "expected", "observed", "status"]
DAY = "2026-10-09"


def load_tool() -> ModuleType:
    path = Path(__file__).parent.parent / "tools" / "verify_proofs.py"
    spec = importlib.util.spec_from_file_location("verify_proofs", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while it loads
    spec.loader.exec_module(module)
    return module


def rule(vendor: str, *records: str) -> Rule:
    names = tuple(r.split(".", 1)[0] for r in records)
    proofs = tuple(Proof(r.split("._domainkey.", 1)[1], r, DAY) for r in records)
    return Rule(vendor, Fixed(names), Source.PATTERN, proofs if len(proofs) > 1 else proofs[0])


def pattern(field: str, value: str, domain: str, record: str) -> Pattern:
    return Pattern("Vendor", field, value, Proof(domain, record, DAY))


def zone() -> Zone:
    return (
        Zone(failing={"slow._domainkey.down.test"})
        .add("k1._domainkey.live.test", "TXT", KEY)
        .add("*._domainkey.wild.test", "TXT", "v=spf1 -all")
        .add("x1._domainkey.empty.test", "A", "192.0.2.1")
        .alias("em._domainkey.alias.test", "em.dkim.vendor.test")
        .add("em.dkim.vendor.test", "TXT", KEY)
        .add("vendor.test", "TXT", "v=spf1 include:_spf.vendor.net -all", "vendor-code: abcdef12")
        .add("vendor.test", "MX", "10 mx1.vendor.net")
        .alias("bounce.vendor.test", "bounces.vendor.net")
        .add("_dmarc.vendor.test", "TXT", "v=DMARC1; p=reject; rua=mailto:r@reports.vendor.net")
        .add("mail.vendor.test", "A", "192.0.2.7")
        .add("7.2.0.192.origin.asn.cymru.com", "TXT", "64500 | 192.0.2.0/24 | US | arin")
    )


RULES = (
    rule("Live", "k1._domainkey.live.test", "em._domainkey.alias.test"),
    rule("Gone", "s1._domainkey.gone.test"),
    rule("Wild", "w1._domainkey.wild.test"),
    rule("Empty", "x1._domainkey.empty.test"),
    rule("Down", "slow._domainkey.down.test"),
)
PATTERNS = (
    pattern("spf_includes", "vendor.net", "vendor.test", "vendor.test"),
    pattern("mx", "vendor.net", "vendor.test", "vendor.test"),
    pattern("return_path", "vendor.net", "vendor.test", "bounce.vendor.test"),
    pattern("reporting", "vendor.net", "vendor.test", "_dmarc.vendor.test"),
    pattern("verification_txt", "vendor-code:", "vendor.test", "vendor.test"),
    pattern("networks", "AS64500", "vendor.test", "mail.vendor.test"),
    pattern("website", "cdn.vendor.net", "vendor.test", "https://vendor.test/"),
    pattern("spf_includes", "other.net", "vendor.test", "vendor.test"),
    pattern("website", "cdn.vendor.net", "vendor.test", "https://vendor.test/gone"),
    pattern("website", "cdn.vendor.net", "vendor.test", "https://vendor.test/blocked"),
)


def web(request: httpx.Request) -> httpx.Response:
    match request.url.path:
        case "/":
            page = '<script src="https://eu.cdn.vendor.net/forms.js"></script>'
            return httpx.Response(200, text=page, headers={"content-type": "text/html"})
        case "/gone":
            return httpx.Response(404)
    return httpx.Response(403)


async def run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *argv: str,
    rules: tuple[Rule, ...] = RULES,
    patterns: tuple[Pattern, ...] = PATTERNS,
) -> tuple[int, str, str]:
    tool = load_tool()
    monkeypatch.setattr(tool, "SystemResolver", lambda timeout: zone())
    monkeypatch.setattr(tool, "load", lambda: tool.items(rules, patterns))
    http = httpx.AsyncClient(transport=httpx.MockTransport(web))
    code = await tool.main(list(argv), http=http)
    out, err = capsys.readouterr()
    return code, out, err


async def test_json_prints_one_object_per_proof(monkeypatch, capsys):
    code, out, err = await run(monkeypatch, capsys, "--json")
    rows = [json.loads(line) for line in out.splitlines()]
    assert all(list(row) == FIELDS for row in rows)
    by_record = {(row["field"], row["record"]): row for row in rows}
    assert by_record[("selectors", "k1._domainkey.live.test")] == {
        "vendor": "Live",
        "field": "selectors",
        "pattern": "k1",
        "domain": "live.test",
        "record": "k1._domainkey.live.test",
        "expected": "TXT record holding a DKIM key (p=)",
        "observed": KEY,
        "status": "found",
    }
    keys = [row for row in rows if row["field"] == "selectors"]
    assert by_record[("selectors", "em._domainkey.alias.test")]["observed"] == (
        f"{KEY} (via em.dkim.vendor.test)"
    )
    assert by_record[("selectors", "s1._domainkey.gone.test")]["observed"] == "NXDOMAIN"
    assert by_record[("selectors", "w1._domainkey.wild.test")]["observed"] == "v=spf1 -all"
    assert by_record[("selectors", "x1._domainkey.empty.test")]["observed"] == "no data"
    assert [row["status"] for row in keys] == [
        "found",
        "found",
        "not found",
        "not found",
        "not found",
        "could not check",
    ]
    assert err == "9 of 16 proofs found, 2 could not be checked\n"
    assert code == 1


async def test_each_kind_of_pattern_is_found_where_its_record_shows_it(monkeypatch, capsys):
    _, out, _ = await run(monkeypatch, capsys, "--json", rules=())
    rows = [json.loads(line) for line in out.splitlines()]
    assert [(row["field"], row["pattern"], row["status"]) for row in rows] == [
        ("spf_includes", "vendor.net", "found"),
        ("mx", "vendor.net", "found"),
        ("return_path", "vendor.net", "found"),
        ("reporting", "vendor.net", "found"),
        ("verification_txt", "vendor-code:", "found"),
        ("networks", "AS64500", "found"),
        ("website", "cdn.vendor.net", "found"),
        ("spf_includes", "other.net", "not found"),
        ("website", "cdn.vendor.net", "not found"),  # the page is gone
        ("website", "cdn.vendor.net", "could not check"),  # the page refused the request
    ]
    assert rows[5]["observed"] == "192.0.2.7 AS64500"
    assert rows[6]["observed"] == "loads eu.cdn.vendor.net"


async def test_text_stays_the_default(monkeypatch, capsys):
    _, out, _ = await run(monkeypatch, capsys)
    lines = out.splitlines()
    assert lines[0].startswith(
        "found      Live selectors [k1, em] k1._domainkey.live.test (2026-10-09): "
    )
    assert lines[2].startswith("not found  Gone selectors [s1] s1._domainkey.gone.test")
    assert lines[5] == (
        "unchecked  Down selectors [slow] slow._domainkey.down.test (2026-10-09): lookup failed"
    )
    assert lines[-1] == "9 of 16 proofs found, 2 could not be checked"


async def test_could_not_check_does_not_fail_the_run(monkeypatch, capsys):
    code, _, err = await run(
        monkeypatch, capsys, "--json", rules=(RULES[0], RULES[4]), patterns=PATTERNS[:1]
    )
    assert code == 0
    assert err == "3 of 4 proofs found, 1 could not be checked\n"
