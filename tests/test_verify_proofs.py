"""tools/verify_proofs.py against the fake zone: the --json shape and what fails the run."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
from conftest import Zone

from sendermap.selectors import Fixed, Proof, Rule, Source

KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
FIELDS = ["vendor", "selector", "domain", "record", "expected", "observed", "status"]


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
    proofs = tuple(Proof(r.split("._domainkey.", 1)[1], r, "2026-10-09") for r in records)
    return Rule(vendor, Fixed(names), Source.PATTERN, proofs if len(proofs) > 1 else proofs[0])


def zone() -> Zone:
    return (
        Zone(failing={"slow._domainkey.down.test"})
        .add("k1._domainkey.live.test", "TXT", KEY)
        .add("*._domainkey.wild.test", "TXT", "v=spf1 -all")
        .add("x1._domainkey.empty.test", "A", "192.0.2.1")
        .alias("em._domainkey.alias.test", "em.dkim.vendor.test")
        .add("em.dkim.vendor.test", "TXT", KEY)
    )


RULES = (
    rule("Live", "k1._domainkey.live.test", "em._domainkey.alias.test"),
    rule("Gone", "s1._domainkey.gone.test"),
    rule("Wild", "w1._domainkey.wild.test"),
    rule("Empty", "x1._domainkey.empty.test"),
    rule("Down", "slow._domainkey.down.test"),
)


async def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *argv: str):
    tool = load_tool()
    monkeypatch.setattr(tool, "SystemResolver", lambda timeout: zone())
    monkeypatch.setattr(tool, "load_rules", lambda: RULES)
    code = await tool.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


async def test_json_prints_one_object_per_proof(monkeypatch, capsys):
    code, out, err = await run(monkeypatch, capsys, "--json")
    rows = [json.loads(line) for line in out.splitlines()]
    assert all(list(row) == FIELDS for row in rows)
    by_record = {row["record"]: row for row in rows}
    assert by_record["k1._domainkey.live.test"] == {
        "vendor": "Live",
        "selector": "k1",
        "domain": "live.test",
        "record": "k1._domainkey.live.test",
        "expected": "TXT record holding a DKIM key (p=)",
        "observed": KEY,
        "status": "found",
    }
    assert by_record["em._domainkey.alias.test"]["observed"] == f"{KEY} (via em.dkim.vendor.test)"
    assert by_record["s1._domainkey.gone.test"]["observed"] == "NXDOMAIN"
    assert by_record["w1._domainkey.wild.test"]["observed"] == "v=spf1 -all"
    assert by_record["x1._domainkey.empty.test"]["observed"] == "no data"
    assert [row["status"] for row in rows] == [
        "found",
        "found",
        "not found",
        "not found",
        "not found",
        "could not check",
    ]
    assert err == "2 of 6 proofs found, 1 could not be checked\n"
    assert code == 1


async def test_text_stays_the_default(monkeypatch, capsys):
    _, out, _ = await run(monkeypatch, capsys)
    lines = out.splitlines()
    assert lines[0].startswith("found      Live [k1, em] k1._domainkey.live.test (2026-10-09): ")
    assert lines[2].startswith("not found  Gone [s1] s1._domainkey.gone.test")
    assert (
        lines[5] == "unchecked  Down [slow] slow._domainkey.down.test (2026-10-09): lookup failed"
    )
    assert lines[-1] == "2 of 6 proofs found, 1 could not be checked"


async def test_could_not_check_does_not_fail_the_run(monkeypatch, capsys):
    tool = load_tool()
    monkeypatch.setattr(tool, "SystemResolver", lambda timeout: zone())
    monkeypatch.setattr(tool, "load_rules", lambda: (RULES[0], RULES[4]))
    assert await tool.main(["--json"]) == 0
    assert capsys.readouterr().err == "2 of 3 proofs found, 1 could not be checked\n"
