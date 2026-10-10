"""Rule 5: every vendor pattern carries a proof, and loading refuses one that does not or whose
record could not show it."""

import copy
import json
from importlib import resources
from typing import Any

import pytest

from sendermap import catalog

SHIPPED: dict[str, Any] = json.loads(
    resources.files("sendermap").joinpath("data/vendors.json").read_text()
)
PROOF = {"domain": "vendor.test", "record": "vendor.test", "date": "2026-10-09"}


def with_entry(field: str, entry: object) -> dict[str, Any]:
    raw = copy.deepcopy(SHIPPED)
    raw["vendors"]["Test Vendor"] = {"category": "Marketing", field: [entry]}
    return raw


def test_every_shipped_pattern_has_a_proof():
    loaded = catalog.load()
    entries = sum(
        len(block.get(field, ()))
        for block in SHIPPED["vendors"].values()
        for field in (*catalog.PATTERN_FIELDS, "other_cname")
    )
    assert entries and len(loaded.patterns) == entries


def test_a_proofed_entry_loads_and_matches():
    raw = with_entry("spf_includes", {"value": "_spf.vendor.test", "proof": PROOF})
    assert catalog.build(raw).spf("_spf.vendor.test") == "Test Vendor"


@pytest.mark.parametrize(
    "entry",
    [
        "_spf.vendor.test",  # the old shape: a bare value
        {"value": "_spf.vendor.test"},
        {"value": "_spf.vendor.test", "proof": None},
    ],
)
def test_an_entry_without_a_proof_is_refused(entry):
    with pytest.raises(ValueError, match="no proof"):
        catalog.build(with_entry("spf_includes", entry))


@pytest.mark.parametrize(
    ("field", "proof", "message"),
    [
        ("spf_includes", {**PROOF, "date": "9 October"}, "not YYYY-MM-DD"),
        ("spf_includes", {**PROOF, "domain": " "}, "no domain"),
        ("mx", {**PROOF, "record": "mail.elsewhere.test"}, "the domain or a name under it"),
        ("reporting", PROOF, "_dmarc.vendor.test or _smtp._tls.vendor.test"),
        ("verification_txt", {**PROOF, "record": "www.vendor.test"}, "the domain itself"),
        ("dkim_cname", PROOF, "a name under _domainkey.vendor.test"),
        ("website", {**PROOF, "record": "http://vendor.test/"}, "an https URL on the domain"),
        ("website", {**PROOF, "record": "https://other.test/"}, "an https URL on the domain"),
    ],
)
def test_a_proof_whose_record_could_not_show_the_pattern_is_refused(field, proof, message):
    with pytest.raises(ValueError, match=message):
        catalog.build(with_entry(field, {"value": "vendor.test", "proof": proof}))


def test_an_other_cname_needs_a_proof_too():
    entry = {"label": "autodiscover", "target": "autodiscover.vendor.test"}
    with pytest.raises(ValueError, match="no proof"):
        catalog.build(with_entry("other_cname", entry))
    proofed = {**entry, "proof": {**PROOF, "record": "autodiscover.vendor.test"}}
    built = catalog.build(with_entry("other_cname", proofed))
    assert built.label_cname("autodiscover", "autodiscover.vendor.test") == (
        "Test Vendor",
        "autodiscover",
    )
