import json
from pathlib import Path
from typing import Any

import pytest

from sendermap.selectors import (
    Fixed,
    Hints,
    Numbered,
    Proof,
    Rule,
    Source,
    build_dictionary,
    load_rules,
    probe_order,
    rank_rules,
)


def proof(name: str, domain: str = "example.test") -> Proof:
    return Proof(domain, f"{name}._domainkey.{domain}", "2026-10-09")


def proof_json(name: str) -> dict[str, str]:
    return {
        "domain": "example.test",
        "record": f"{name}._domainkey.example.test",
        "date": "2026-10-09",
    }


def vendors_file(tmp_path: Path, vendors: dict[str, Any]) -> Path:
    path = tmp_path / "vendors.json"
    path.write_text(json.dumps({"vendors": vendors}), encoding="utf-8")
    return path


def test_fixed_expands_to_its_names():
    assert list(Fixed(("a", "b")).expand()) == ["a", "b"]


def test_numbered_counts_from_one():
    assert list(Numbered("s", 3).expand()) == ["s1", "s2", "s3"]


def test_vendor_docs_without_reference_is_rejected():
    with pytest.raises(ValueError):
        Rule("X", Fixed(("x",)), Source.VENDOR_DOCS, proof("x"))


def test_a_name_claimed_by_two_vendors_keeps_both_claims():
    rules = (
        Rule("A", Fixed(("s1",)), Source.PATTERN, proof("s1")),
        Rule("B", Numbered("s", 1), Source.PATTERN, proof("s1")),
    )
    found = build_dictionary(rules)
    assert {c.vendor for c in found["s1"]} == {"A", "B"}


def test_rules_load_from_the_vendor_blocks(tmp_path: Path):
    rules_file = vendors_file(
        tmp_path,
        {
            "Google Workspace": {
                "category": "Mailbox",
                "selectors": [
                    {
                        "shape": {"kind": "fixed", "names": ["google"]},
                        "source": "vendor_docs",
                        "reference": "https://example.test/docs",
                        "proof": proof_json("google"),
                    }
                ],
            },
            "No Selectors": {"category": "Marketing"},
        },
    )
    rules = load_rules(rules_file)
    found = build_dictionary(rules)
    assert found["google"][0].vendor == "Google Workspace"
    assert found["google"][0].proof == proof("google")
    assert len(rules) == 1


@pytest.mark.parametrize(
    ("entry_proof", "message"),
    [
        (None, "Example Vendor example: no proof"),
        ({**proof_json("example"), "record": "  "}, "Example Vendor example: proof has no record"),
    ],
)
def test_a_selector_entry_without_a_proof_is_rejected(tmp_path: Path, entry_proof, message):
    entry = {"shape": {"kind": "fixed", "names": ["example"]}, "source": "pattern"}
    if entry_proof is not None:
        entry["proof"] = entry_proof
    rules_file = vendors_file(tmp_path, {"Example Vendor": {"selectors": [entry]}})
    with pytest.raises(ValueError, match=message):
        load_rules(rules_file)


GOOGLE = Rule(
    "Google Workspace",
    Fixed(("google",)),
    Source.PATTERN,
    proof("google"),
    hints=Hints(mx=("google.com",), spf=("_spf.google.com",)),
    hints_reference=("https://example.test/google",),
)
MICROSOFT = Rule(
    "Microsoft 365",
    Numbered("selector", 2),
    Source.PATTERN,
    proof("selector1"),
    hints=Hints(mx=("mail.protection.outlook.com",), spf=("spf.protection.outlook.com",)),
    hints_reference=("https://example.test/microsoft",),
)
NO_HINTS = Rule("Example Vendor", Fixed(("example",)), Source.PATTERN, proof("example"))
RULES = (MICROSOFT, NO_HINTS, GOOGLE)


def test_a_rule_whose_mx_hint_matches_moves_first_and_the_rest_keep_order():
    ranked = rank_rules(RULES, ["aspmx.l.google.com"], [])
    assert ranked == (GOOGLE, MICROSOFT, NO_HINTS)


def test_hosts_match_regardless_of_case_or_trailing_dot():
    assert rank_rules(RULES, ["ASPMX.L.Google.com."], [])[0] is GOOGLE
    assert rank_rules(RULES, [], ["_SPF.Google.com."])[0] is GOOGLE


def test_spf_include_matches_exactly():
    assert rank_rules(RULES, [], ["_SPF.google.com"])[0] is GOOGLE
    assert rank_rules(RULES, [], ["google.com"]) == RULES


def test_mx_suffix_matches_on_a_label_boundary():
    assert rank_rules(RULES, ["notgoogle.com"], []) == RULES


def test_no_match_keeps_original_order():
    assert rank_rules(RULES, ["mx.example.net"], ["spf.example.net"]) == RULES


def test_a_rule_without_hints_never_moves():
    ranked = rank_rules(RULES, ["example-com.mail.protection.outlook.com"], [])
    assert ranked == (MICROSOFT, NO_HINTS, GOOGLE)
    assert rank_rules((NO_HINTS,), ["aspmx.l.google.com"], ["_spf.google.com"]) == (NO_HINTS,)


def pattern_entry(shape: dict[str, Any], name: str) -> dict[str, Any]:
    return {"shape": shape, "source": "pattern", "proof": proof_json(name)}


def test_hints_are_normalised_on_load(tmp_path: Path):
    rules_file = vendors_file(
        tmp_path,
        {
            "Google Workspace": {
                "selectors": [pattern_entry({"kind": "fixed", "names": ["google"]}, "google")],
                "hints": {"mx": ["Google.com."], "spf": ["_spf.google.com"]},
                "hints_reference": ["https://example.test/hints"],
            },
            "Example Vendor": {
                "selectors": [pattern_entry({"kind": "fixed", "names": ["example"]}, "example")],
            },
        },
    )
    google, example = load_rules(rules_file)
    assert google.hints == Hints(mx=("google.com",), spf=("_spf.google.com",))
    assert google.hints_reference == ("https://example.test/hints",)
    assert example.hints == Hints()


def test_selector_names_are_lowercased_on_load(tmp_path: Path):
    rules_file = vendors_file(
        tmp_path,
        {
            "A": {"selectors": [pattern_entry({"kind": "fixed", "names": ["Google"]}, "google")]},
            "B": {
                "selectors": [
                    pattern_entry(
                        {"kind": "numbered", "prefix": "Selector", "stop": 1}, "selector1"
                    )
                ]
            },
        },
    )
    assert list(build_dictionary(load_rules(rules_file))) == ["google", "selector1"]


def test_an_unknown_shape_kind_is_rejected(tmp_path: Path):
    shape = {"kind": "dated", "prefix": "ex", "years_back": 1}
    rules_file = vendors_file(
        tmp_path, {"Example Vendor": {"selectors": [pattern_entry(shape, "ex")]}}
    )
    with pytest.raises(ValueError, match="Example Vendor: unknown shape kind 'dated'"):
        load_rules(rules_file)


def test_shipped_rules_split_mailchimp_by_provenance():
    mailchimp = [r for r in load_rules() if r.vendor == "Mailchimp"]
    assert [(r.source, list(r.shape.expand())) for r in mailchimp] == [
        (Source.VENDOR_DOCS, ["k2"]),
        (Source.PATTERN, ["k1"]),
        (Source.PATTERN, ["k3"]),
    ]


@pytest.mark.parametrize(
    ("entry_proof", "message"),
    [
        (proof_json("k1"), "2 names need 2 proofs"),
        ([proof_json("k1")], "2 names need 2 proofs"),
        (
            [proof_json("k3"), proof_json("k1")],
            r"proof record .k3\._domainkey\.example\.test. does not name k1",
        ),
    ],
)
def test_a_fixed_shape_with_several_names_needs_one_proof_per_name(
    tmp_path: Path, entry_proof, message
):
    entry = {"shape": {"kind": "fixed", "names": ["k1", "k3"]}, "source": "pattern"}
    rules_file = vendors_file(
        tmp_path, {"Example Vendor": {"selectors": [{**entry, "proof": entry_proof}]}}
    )
    with pytest.raises(ValueError, match=f"Example Vendor k1, k3: {message}"):
        load_rules(rules_file)


def test_each_name_in_a_fixed_shape_carries_its_own_proof(tmp_path: Path):
    entry = {
        "shape": {"kind": "fixed", "names": ["k1", "k3"]},
        "source": "pattern",
        "proof": [proof_json("k1"), proof_json("k3")],
    }
    rules_file = vendors_file(tmp_path, {"Example Vendor": {"selectors": [entry]}})
    found = build_dictionary(load_rules(rules_file))
    assert found["k1"][0].proof == proof("k1")
    assert found["k3"][0].proof == proof("k3")


def test_a_hints_reference_given_as_one_string_is_rejected(tmp_path: Path):
    rules_file = vendors_file(
        tmp_path,
        {
            "Google Workspace": {
                "selectors": [pattern_entry({"kind": "fixed", "names": ["google"]}, "google")],
                "hints": {"mx": ["google.com"]},
                "hints_reference": "https://example.test/hints",
            }
        },
    )
    with pytest.raises(ValueError, match="must be a list"):
        load_rules(rules_file)


def test_hints_without_hints_reference_are_rejected():
    with pytest.raises(ValueError, match="hints_reference"):
        Rule("X", Fixed(("x",)), Source.PATTERN, proof("x"), hints=Hints(mx=("x.test",)))


def test_hints_reference_without_hints_is_accepted():
    assert Rule("X", Fixed(("x",)), Source.PATTERN, proof("x"), hints_reference=("https://x.test",))


def test_probe_order_moves_rule_names_ahead_and_keeps_the_sweep():
    sweep = ("k1", "Google", "selector2", "zz", "selector1")
    order = probe_order((MICROSOFT, NO_HINTS, GOOGLE), sweep)
    assert order == ("selector1", "selector2", "google", "k1", "zz")
