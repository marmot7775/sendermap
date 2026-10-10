from datetime import date
from pathlib import Path

import pytest

from sendermap.selectors import (
    Dated,
    Fixed,
    Numbered,
    Rule,
    Source,
    build_dictionary,
    load_rules,
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
