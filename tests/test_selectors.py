from pathlib import Path

import pytest

from sendermap.selectors import (
    Fixed,
    Hints,
    Numbered,
    Rule,
    Source,
    build_dictionary,
    load_rules,
    probe_order,
    rank_rules,
)


def test_fixed_expands_to_its_names():
    assert list(Fixed(("a", "b")).expand()) == ["a", "b"]


def test_numbered_counts_from_one():
    assert list(Numbered("s", 3).expand()) == ["s1", "s2", "s3"]


def test_vendor_docs_without_reference_is_rejected():
    with pytest.raises(ValueError):
        Rule("X", Fixed(("x",)), Source.VENDOR_DOCS)


def test_a_name_claimed_by_two_vendors_keeps_both_claims():
    rules = (
        Rule("A", Fixed(("s1",)), Source.PATTERN),
        Rule("B", Numbered("s", 1), Source.PATTERN),
    )
    found = build_dictionary(rules)
    assert {c.vendor for c in found["s1"]} == {"A", "B"}


def test_rules_load_from_a_yaml_file(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- vendor: Google Workspace\n"
        "  shape: {kind: fixed, names: [google]}\n"
        "  source: vendor_docs\n"
        "  reference: https://example.test/docs\n",
        encoding="utf-8",
    )
    rules = load_rules(rules_file)
    found = build_dictionary(rules)
    assert found["google"][0].vendor == "Google Workspace"


GOOGLE = Rule(
    "Google Workspace",
    Fixed(("google",)),
    Source.PATTERN,
    hints=Hints(mx=("google.com",), spf=("_spf.google.com",)),
    hints_reference=("https://example.test/google",),
)
MICROSOFT = Rule(
    "Microsoft 365",
    Numbered("selector", 2),
    Source.PATTERN,
    hints=Hints(mx=("mail.protection.outlook.com",), spf=("spf.protection.outlook.com",)),
    hints_reference=("https://example.test/microsoft",),
)
NO_HINTS = Rule("Example Vendor", Fixed(("example",)), Source.PATTERN)
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


def test_hints_are_normalised_on_load(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- vendor: Google Workspace\n"
        "  shape: {kind: fixed, names: [google]}\n"
        "  source: pattern\n"
        "  hints: {mx: [Google.com.], spf: [_spf.google.com]}\n"
        "  hints_reference: [https://example.test/hints]\n"
        "- vendor: Example Vendor\n"
        "  shape: {kind: fixed, names: [example]}\n"
        "  source: pattern\n",
        encoding="utf-8",
    )
    google, example = load_rules(rules_file)
    assert google.hints == Hints(mx=("google.com",), spf=("_spf.google.com",))
    assert google.hints_reference == ("https://example.test/hints",)
    assert example.hints == Hints()


def test_selector_names_are_lowercased_on_load(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- vendor: A\n"
        "  shape: {kind: fixed, names: [Google]}\n"
        "  source: pattern\n"
        "- vendor: B\n"
        "  shape: {kind: numbered, prefix: Selector, stop: 1}\n"
        "  source: pattern\n",
        encoding="utf-8",
    )
    assert list(build_dictionary(load_rules(rules_file))) == ["google", "selector1"]


def test_an_unknown_shape_kind_is_rejected(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- vendor: Example Vendor\n"
        "  shape: {kind: dated, prefix: ex, years_back: 1}\n"
        "  source: pattern\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Example Vendor: unknown shape kind 'dated'"):
        load_rules(rules_file)


def test_shipped_rules_split_mailchimp_by_provenance():
    mailchimp = [r for r in load_rules() if r.vendor == "Mailchimp"]
    by_source = {r.source: list(r.shape.expand()) for r in mailchimp}
    assert by_source == {Source.VENDOR_DOCS: ["k2"], Source.PATTERN: ["k1", "k3"]}


def test_a_hints_reference_given_as_one_string_is_rejected(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- vendor: Google Workspace\n"
        "  shape: {kind: fixed, names: [google]}\n"
        "  source: pattern\n"
        "  hints: {mx: [google.com]}\n"
        "  hints_reference: https://example.test/hints\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must be a list"):
        load_rules(rules_file)


def test_hints_without_hints_reference_are_rejected():
    with pytest.raises(ValueError, match="hints_reference"):
        Rule("X", Fixed(("x",)), Source.PATTERN, hints=Hints(mx=("x.test",)))


def test_hints_reference_without_hints_is_accepted():
    assert Rule("X", Fixed(("x",)), Source.PATTERN, hints_reference=("https://x.test",))


def test_probe_order_moves_rule_names_ahead_and_keeps_the_sweep():
    sweep = ("k1", "Google", "selector2", "zz", "selector1")
    order = probe_order((MICROSOFT, NO_HINTS, GOOGLE), sweep)
    assert order == ("selector1", "selector2", "google", "k1", "zz")
