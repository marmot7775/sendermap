"""Backed only selectors: a plain name such as s1 credits its vendor (Klaviyo) only where the
domain's SPF, MX or an NS delegation already shows that vendor, and names nobody otherwise."""

import copy
import json
from importlib import resources
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone
from test_dkim import KEY_2048
from test_verify_proofs import load_tool

from sendermap import catalog, map_domain
from sendermap.model import Evidence, Kind

SHIPPED: dict[str, Any] = json.loads(
    resources.files("sendermap").joinpath("data/vendors.json").read_text()
)
KLAVIYO_NS = ("ns1.klaviyo.com", "ns2.klaviyo.com", "ns3.klaviyo.com", "ns4.klaviyo.com")
C = catalog.load()


def test_s1_and_s2_are_klaviyos_backed_only_names_with_a_proof() -> None:
    assert C.backed_only_selectors == {"s1": "Klaviyo", "s2": "Klaviyo"}
    assert C.backed_only_proofs["s2"].record == "s2._domainkey.klaviyo.com"
    assert C.backs("Klaviyo") >= {"s1", "s2", "kl", "kl1", "kl2"}
    assert not C.backs("SendGrid") & {"s1", "s2"}  # still on SendGrid's list, backed by nobody
    assert {"s1", "s2"} <= C.selectors_of("SendGrid")


def test_the_proofs_tool_rechecks_each_backed_only_proof() -> None:
    items = [i for i in load_tool().load() if i.field == "selectors" and i.pattern in ("s1", "s2")]
    assert [(i.vendor, i.shown, i.proof.record) for i in items] == [
        ("Klaviyo", "s1", "s1._domainkey.klaviyo.com"),
        ("Klaviyo", "s2", "s2._domainkey.klaviyo.com"),
    ]


def test_the_rule_order_in_dkim_key() -> None:
    assert C.dkim_key("s1", (), backed="Klaviyo") == "Klaviyo"
    assert C.dkim_key("s1", (), backed="SendGrid") is None
    assert C.dkim_key("s1", (), backed=None) is None
    # A CNAME still decides first: SendGrid's own zone is SendGrid's key.
    assert C.dkim_key("s1", ("s1.domainkey.u1.wl1.sendgrid.net",), backed=None) == "SendGrid"
    # selector1 and selector2 still name nobody without Microsoft's CNAME, backed or not.
    assert C.dkim_key("selector1", (), backed="Microsoft 365") is None


def with_rule(entry: dict[str, Any]) -> dict[str, Any]:
    raw: dict[str, Any] = copy.deepcopy(SHIPPED)
    raw["rules"]["backed_only_selectors"] = {"s1": entry}
    return raw


PROOF = {"domain": "klaviyo.com", "record": "s1._domainkey.klaviyo.com", "date": "2026-10-11"}


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"vendor": "Nobody", "proof": PROOF}, "not in the file"),
        ({"vendor": "Klaviyo"}, "no proof"),
        ({"vendor": "Klaviyo", "proof": {**PROOF, "record": "s2._domainkey.klaviyo.com"}}, "not"),
        ({"vendor": "Klaviyo", "proof": {**PROOF, "date": "11 Oct"}}, "YYYY-MM-DD"),
    ],
)
def test_a_backed_only_name_without_its_vendor_or_proof_is_refused(
    entry: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        catalog.build(with_rule(entry))


async def test_s1_where_spf_shows_klaviyo_is_klaviyos_with_the_spf_claim_as_support(
    offline: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Klaviyo publishes no SPF include today, so the test catalog gives it one.
    raw: dict[str, Any] = copy.deepcopy(SHIPPED)
    proof = {"domain": "klaviyo.com", "record": "klaviyo.com", "date": "2026-10-11"}
    raw["vendors"]["Klaviyo"]["spf_includes"] = [{"value": "spf.klaviyo.test", "proof": proof}]
    monkeypatch.setattr(catalog, "load", lambda: catalog.build(raw))
    zone = (
        Zone()
        .add("acme.test", "TXT", "v=spf1 include:spf.klaviyo.test -all")
        .add("spf.klaviyo.test", "TXT", "v=spf1 ip4:192.0.2.0/24 -all")
        .add("s1._domainkey.acme.test", "TXT", KEY_2048)
    )
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    (klaviyo,) = [s for s in result.services if s.name == "Klaviyo"]
    (key,) = [c for c in klaviyo.claims if c.kind is Kind.DKIM_NAME]
    assert key.evidence.name == "s1._domainkey.acme.test"
    spf = Evidence("acme.test", "TXT", "include:spf.klaviyo.test", CHECKED)
    assert key.supporting == (spf,)


async def test_s1_where_only_sendgrid_shows_credits_nobody_and_is_listed_unattributed(
    offline: httpx.AsyncClient,
) -> None:
    zone = (
        Zone()
        .add("acme.test", "TXT", "v=spf1 include:sendgrid.net -all")
        .add("s1._domainkey.acme.test", "TXT", KEY_2048)
    )
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    assert not [c for s in result.services for c in s.claims if c.kind is Kind.DKIM_NAME]
    (unknown,) = [u for u in result.unknowns if u.what == "DKIM key"]
    assert unknown.value == "s1" and unknown.where == "acme.test"
    assert unknown.evidence.name == "s1._domainkey.acme.test"
    assert unknown.evidence.value.startswith("v=DKIM1")


async def test_a_klaviyo_delegation_asks_and_credits_s1_and_s2_under_it(
    offline: httpx.AsyncClient,
) -> None:
    # Klaviyo's nameservers answer no such name at _domainkey.send.<domain>, so only backed
    # names are asked there; s1 and s2 are now among them.
    zone = (
        Zone()
        .add("send.acme.test", "NS", *KLAVIYO_NS)
        .add("s1._domainkey.send.acme.test", "TXT", KEY_2048)
        .add("s2._domainkey.send.acme.test", "TXT", KEY_2048)
    )
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    (klaviyo,) = [s for s in result.services if s.name == "Klaviyo"]
    keys = [c for c in klaviyo.claims if c.kind is Kind.DKIM_NAME]
    assert [c.evidence.name for c in keys] == [
        "s1._domainkey.send.acme.test",
        "s2._domainkey.send.acme.test",
    ]
    ns = Evidence("send.acme.test", "NS", "ns1.klaviyo.com", CHECKED)
    assert all(c.supporting == (ns,) for c in keys)
