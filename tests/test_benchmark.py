"""tools/benchmark.py offline: how unknowns group across domains, the measures a run reports,
and what a comparison says. No map is made; every run here is written by hand."""

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def load_tool() -> ModuleType:
    path = Path(__file__).parent.parent / "tools" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while it loads
    spec.loader.exec_module(module)
    return module


bench = load_tool()


def result(senders: dict[str, str] | None = None, unknowns: Sequence[tuple[str, str]] = ()) -> Any:
    return {
        "senders": senders or {},
        "reporting": [],
        "unknowns": [{"what": w, "value": v} for w, v in unknowns],
        "gaps": {"dkim": 1},
        "lookups": 100,
        "elapsed": 2.0,
        "resolver": "the system resolver",
    }


def run(version: str, domains: dict[str, Any]) -> Any:
    return {"version": version, "checked_at": "2026-10-25T00:00:00+00:00", "domains": domains}


@pytest.mark.parametrize(
    ("host", "zone"),
    [
        ("_spf.vendor.com", "vendor.com"),
        ("vendor.com", "vendor.com"),
        ("mx1.mail.example.co.uk", "example.co.uk"),
        ("a.b.example.com.au.", "example.com.au"),
        ("co.uk", "co.uk"),
    ],
)
def test_zone_keeps_the_registrable_part(host: str, zone: str) -> None:
    assert bench.zone(host) == zone


def test_group_key_by_kind() -> None:
    assert bench.group_key("SPF include", "_spf.Vendor.com") == "vendor.com"
    assert bench.group_key("DKIM key", "selector1 via selector1._domainkey.x.com") == "selector1"
    address = "151.106.133.162/32 (AS14340, SALESFORCE - Salesforce.com, Inc., US)"
    assert (
        bench.group_key("IP address in SPF", address)
        == "AS14340, SALESFORCE - Salesforce.com, Inc., US"
    )
    assert bench.group_key("IP address in SPF", "192.0.2.1") == "192.0.2.1"


def test_every_cname_is_one_kind() -> None:
    assert bench.kind("CNAME at bounce") == bench.kind("CNAME at email") == "CNAME"
    assert bench.kind("SPF include") == "SPF include"


def test_read_domains_drops_comments_blanks_and_repeats(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text("# header\nA.com\n\nb.com  # note\na.com\n")
    assert bench.read_domains(path) == ["a.com", "b.com"]


def test_leads_rank_by_domains_and_split_names_from_addresses() -> None:
    domains = {
        "a.com": result(unknowns=[("SPF include", "_spf.vendor.com"), ("IP range in SPF", "x")]),
        "b.com": result(unknowns=[("SPF include", "spf2.vendor.com"), ("mail server", "mx.b.net")]),
    }
    named = bench.leads(domains, named=True)
    assert [(ld.what, ld.key, ld.domains) for ld in named] == [
        ("SPF include", "vendor.com", 2),
        ("mail server", "b.net", 1),
    ]
    assert named[0].example == "_spf.vendor.com"
    assert [ld.key for ld in bench.leads(domains, named=False)] == ["x"]


def test_numbers_count_shared_groups_and_fully_named_domains() -> None:
    data = run(
        "1",
        {
            "a.com": result({"SendGrid": "In use"}, [("SPF include", "_spf.vendor.com")]),
            "b.com": result({}, [("SPF include", "_spf.vendor.com"), ("CNAME at t", "t.solo.io")]),
            "c.com": result({"Mailgun": "Configured"}, [("IP address in SPF", "192.0.2.1")]),
            "d.com": {"error": "Timeout: no answer"},
        },
    )
    n = bench.numbers(data)
    assert (n["domains"], n["mapped"], n["failed"]) == (4, 3, 1)
    assert (n["senders"], n["no sender found"]) == (2, 1)
    assert (n["named unknowns"], n["named unknown groups"], n["shared named groups"]) == (3, 2, 1)
    assert (n["domains fully named"], n["fully named %"], n["address unknowns"]) == (1, 33.3, 1)


def test_report_lists_failures() -> None:
    text = bench.report(run("1", {"a.com": result(), "d.com": {"error": "Timeout: no answer"}}))
    assert "## Failed" in text
    assert "- d.com: Timeout: no answer" in text


def test_compare_names_services_gained_and_lost() -> None:
    old = run(
        "1", {"a.com": result({"SendGrid": "In use"}), "b.com": result({"Mailgun": "Likely"})}
    )
    new = run(
        "2", {"a.com": result({"SendGrid": "In use", "Klaviyo": "Configured"}), "b.com": result()}
    )
    text = bench.compare(old, new)
    assert "| a.com | Klaviyo | - |" in text
    assert "| b.com | - | Mailgun |" in text
    assert "| senders | 2 | 2 | 0 |" in text


def test_compare_with_no_change_says_none() -> None:
    same = run("1", {"a.com": result({"SendGrid": "In use"})})
    assert bench.compare(same, same).rstrip().endswith("None.")


def test_an_unannounced_address_groups_by_itself() -> None:
    one = "203.0.113.0/24 (no one network announces it)"
    two = "198.51.100.7 (no one network announces it; listed by Vendor)"
    assert bench.group_key("IP range in SPF", one) == "203.0.113.0/24"
    assert bench.group_key("IP address in SPF", two) == "198.51.100.7"


def test_a_shared_selector_name_is_not_a_shared_vendor() -> None:
    data = run(
        "1",
        {
            "a.com": result(unknowns=[("DKIM key", "mail")]),
            "b.com": result(unknowns=[("DKIM key", "mail")]),
        },
    )
    n = bench.numbers(data)
    assert (n["named unknown groups"], n["shared named groups"]) == (1, 0)
