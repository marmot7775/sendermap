from datetime import date
from pathlib import Path

import pytest

from sendermap.selectors import (
    Dated,
    Fixed,
    Hints,
    Numbered,
    Rule,
    Source,
    build_dictionary,
    load_rules,
    rank_rules,
)

TODAY = date(2026, 10, 9)


def test_fixed_expands_to_its_names():
    assert list(Fixed(("a", "b")).expand(TODAY)) == ["a", "b"]


def test_numbered_counts_from_one():
    assert list(Numbered("s", 3).expand(TODAY)) == ["s1", "s2", "s3"]


def test_dated_covers_every_month_back_to_years_back():
    names = list(Dated("ses", 1).expand(TODAY))
    assert names[0] == "ses202501"
    assert names[-1] == "ses202612"
    assert len(names) == 24


def test_vendor_docs_without_reference_is_rejected():
    with pytest.raises(ValueError):
        Rule("X", Fixed(("x",)), Source.VENDOR_DOCS)


def test_collisions_keep_every_claim():
    rules = (
        Rule("A", Fixed(("s1",)), Source.PATTERN),
        Rule("B", Numbered("s", 1), Source.PATTERN),
    )
    found = build_dictionary(rules, TODAY)
    assert {c.vendor for c in found["s1"]} == {"A", "B"}


def test_rules_file_round_trips(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- vendor: Google Workspace\n"
        "  shape: {kind: fixed, names: [google]}\n"
        "  source: vendor_docs\n"
        "  reference: https://example.test/docs\n",
        encoding="utf-8",
    )
    rules = load_rules(rules_file)
    found = build_dictionary(rules, TODAY)
    assert found["google"][0].vendor == "Google Workspace"


GOOGLE = Rule(
    "Google Workspace",
    Fixed(("google",)),
    Source.PATTERN,
    hints=Hints(mx=("google.com",), spf=("_spf.google.com",)),
)
MICROSOFT = Rule(
    "Microsoft 365",
    Numbered("selector", 2),
    Source.PATTERN,
    hints=Hints(mx=("mail.protection.outlook.com",), spf=("spf.protection.outlook.com",)),
)
NO_HINTS = Rule("Amazon SES", Fixed(("ses",)), Source.PATTERN)
RULES = (MICROSOFT, NO_HINTS, GOOGLE)


def test_mx_at_google_puts_google_first():
    ranked = rank_rules(RULES, ["ASPMX.L.Google.com."], [])
    assert ranked == (GOOGLE, MICROSOFT, NO_HINTS)


def test_spf_include_matches_exactly():
    assert rank_rules(RULES, [], ["_SPF.google.com"])[0] is GOOGLE
    assert rank_rules(RULES, [], ["google.com"]) == RULES


def test_mx_suffix_matches_on_a_label_boundary():
    assert rank_rules(RULES, ["notgoogle.com"], []) == RULES


def test_no_match_keeps_original_order():
    assert rank_rules(RULES, ["mx.example.net"], ["spf.example.net"]) == RULES


def test_rule_without_hints_is_unaffected():
    assert NO_HINTS.hints == Hints()
    ranked = rank_rules(RULES, ["example-com.mail.protection.outlook.com"], [])
    assert ranked == (MICROSOFT, NO_HINTS, GOOGLE)
    assert rank_rules((NO_HINTS,), ["aspmx.l.google.com"], ["_spf.google.com"]) == (NO_HINTS,)


def test_hints_parse_from_the_rules_file(tmp_path: Path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        "- vendor: Google Workspace\n"
        "  shape: {kind: fixed, names: [google]}\n"
        "  source: pattern\n"
        "  hints: {mx: [Google.com.], spf: [_spf.google.com]}\n"
        "- vendor: Amazon SES\n"
        "  shape: {kind: fixed, names: [ses]}\n"
        "  source: pattern\n",
        encoding="utf-8",
    )
    google, ses = load_rules(rules_file)
    assert google.hints == Hints(mx=("google.com",), spf=("_spf.google.com",))
    assert ses.hints == Hints()


def test_shipped_rules_split_mailchimp_by_provenance():
    mailchimp = [r for r in load_rules() if r.vendor == "Mailchimp"]
    by_source = {r.source: list(r.shape.expand(TODAY)) for r in mailchimp}
    assert by_source == {Source.VENDOR_DOCS: ["k2"], Source.PATTERN: ["k1", "k3"]}
