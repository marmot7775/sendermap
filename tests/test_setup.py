"""Setups: each vendor's documented setup read from what the map already asked. Each state with
its evidence, the findings a setup raises, the bounce domain folded into the setup above it,
complete, the views, the loading rules, and that a setup asks DNS nothing more."""

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone
from rich.console import Console

from sendermap import catalog, map_domain, setup
from sendermap.model import Need, SenderMap, Service, Severity, State, Tier
from sendermap.render import html, markdown, text

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392
MX = "0 example-test.mail.protection.outlook.com"
SPF_M365 = "v=spf1 include:spf.protection.outlook.com -all"


def m365(domain: str = "example.test", *, spf: str = SPF_M365, signed: bool = False) -> Zone:
    """Microsoft 365 in MX and, unless told otherwise, in SPF; keys only when `signed`."""
    zone = Zone().add(domain, "MX", MX).add(domain, "TXT", spf).selectors_exist(domain)
    if signed:
        for n in (1, 2):
            target = f"selector{n}-example-test._domainkey.example.onmicrosoft.com"
            zone.alias(f"selector{n}._domainkey.{domain}", target).add(target, "TXT", KEY)
    return zone


async def mapped(zone: Zone, http: httpx.AsyncClient, domain: str = "example.test") -> SenderMap:
    return await map_domain(domain, checked_at=CHECKED, resolver=zone, http=http, use_web=False)


def service(result: SenderMap, name: str) -> Service:
    return next(s for s in result.services if s.name == name)


def states(result: SenderMap, name: str, where: str = "example.test") -> dict[str, str]:
    found = next(s for s in service(result, name).setups if s.where == where)
    return {i.record: i.state.value for i in found.items}


def item(result: SenderMap, name: str, record: str, where: str = "example.test") -> Any:
    found = next(s for s in service(result, name).setups if s.where == where)
    return next(i for i in found.items if i.record == record)


def setup_findings(result: SenderMap) -> list[tuple[Severity, str]]:
    names = set(catalog.load().setups)
    return [
        (f.severity, f.title)
        for f in result.findings
        if any(f.title.startswith(n) for n in names) and "key" not in f.title
    ]


async def test_a_mailbox_in_mx_that_does_not_sign_is_a_risk_with_the_negative_answers(
    offline: httpx.AsyncClient,
) -> None:
    result = await mapped(m365(), offline)
    (found,) = service(result, "Microsoft 365").setups
    assert found.complete is False
    assert setup.line(found) == (
        "Setup at example.test: SPF present, DKIM missing (no key at selector1._domainkey or "
        "selector2._domainkey, names that do not exist), "
        "MX present, bounce CNAME not needed."
    )
    dkim = item(result, "Microsoft 365", "dkim")
    assert [str(e) for e in dkim.evidence] == [
        "selector1._domainkey.example.test TXT no such name",
        "selector2._domainkey.example.test TXT no such name",
        "_domainkey.example.test TXT no record of this type",  # the absence's: selectors exist
    ]
    assert dkim.asked == (
        "TXT at selector1._domainkey.example.test and TXT at selector2._domainkey.example.test"
    )
    assert [str(e) for e in item(result, "Microsoft 365", "spf").evidence] == [
        "example.test TXT include:spf.protection.outlook.com"
    ]
    (risk,) = [f for f in result.findings if "does not sign" in f.title]
    assert risk.severity is Severity.RISK
    assert risk.title == "Microsoft 365 receives the domain's mail and does not sign it"
    assert risk.evidence == dkim.evidence


async def test_a_mailbox_in_mx_missing_from_spf_is_a_risk_with_the_record_read(
    offline: httpx.AsyncClient,
) -> None:
    result = await mapped(m365(spf="v=spf1 include:mailgun.org -all", signed=True), offline)
    assert states(result, "Microsoft 365") == {
        "spf": "missing",
        "dkim": "present",
        "mx": "present",
        "return_path": "not needed",
    }
    spf = item(result, "Microsoft 365", "spf")
    assert spf.detail == "the record does not authorize spf.protection.outlook.com"
    assert [str(e) for e in spf.evidence] == ["example.test TXT v=spf1 include:mailgun.org -all"]
    assert setup_findings(result) == [
        (Severity.RISK, "Microsoft 365 receives the domain's mail and is not in its SPF")
    ]


async def test_no_spf_record_at_all_is_missing_with_that_answer(
    offline: httpx.AsyncClient,
) -> None:
    result = await mapped(m365(spf="google-site-verification=abcdefgh", signed=True), offline)
    spf = item(result, "Microsoft 365", "spf")
    assert (spf.state, spf.detail) == (State.MISSING, "no SPF record")
    assert [str(e) for e in spf.evidence] == ["example.test TXT no SPF record (v=spf1)"]


async def test_missing_keys_are_worded_by_the_zones_denial_class(
    offline: httpx.AsyncClient,
) -> None:
    compact = m365()
    compact.compact = True
    dkim = item(await mapped(compact, offline), "Microsoft 365", "dkim")
    assert dkim.state is State.MISSING
    assert dkim.detail == (
        "no key at selector1._domainkey or selector2._domainkey, names with no TXT record; this "
        "zone gives that answer for every name that does not exist"
    )


async def test_no_domainkey_in_a_classic_zone_is_missing_with_the_absences_evidence(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("example.test", "MX", MX).add("example.test", "TXT", SPF_M365)
    result = await mapped(zone, offline)
    dkim = item(result, "Microsoft 365", "dkim")
    assert dkim.state is State.MISSING
    assert [str(e) for e in dkim.evidence] == [
        "selector1._domainkey.example.test TXT no such name",
        "selector2._domainkey.example.test TXT no such name",
        "_domainkey.example.test TXT no such name",
        "sendermap-wildcard-check._domainkey.example.test TXT no such name",
    ]


async def test_a_failed_spf_lookup_is_not_checked_and_leaves_complete_unknown(
    offline: httpx.AsyncClient,
) -> None:
    zone = m365(signed=True)
    zone.failing.add("example.test")
    zone.records.pop(("example.test", "MX"))
    zone.add("example.test", "TXT", "MS=ms12345678")  # unreachable: the name fails
    result = await mapped(zone, offline)
    assert service(result, "Microsoft 365").setups[0].complete is None
    spf = item(result, "Microsoft 365", "spf")
    assert (spf.state, spf.detail) == (State.NOT_CHECKED, "SPF: TXT at example.test: lookup failed")


async def test_a_hosted_spf_record_is_not_checked_with_the_reason(
    offline: httpx.AsyncClient,
) -> None:
    hosted = "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all"
    result = await mapped(m365(spf=hosted, signed=True), offline)
    spf = item(result, "Microsoft 365", "spf")
    assert spf.state is State.NOT_CHECKED
    assert spf.detail == (
        "managed through Valimail, which can authorize services without naming them"
    )
    assert spf.evidence[0].value == hosted
    assert service(result, "Microsoft 365").setups[0].complete is None
    assert setup_findings(result) == []


async def test_a_wildcard_under_domainkey_is_not_checked(offline: httpx.AsyncClient) -> None:
    zone = m365().add("*._domainkey.example.test", "TXT", KEY)
    dkim = item(await mapped(zone, offline), "Microsoft 365", "dkim")
    assert dkim.state is State.NOT_CHECKED
    assert dkim.detail == "every name under _domainkey.example.test answers with a key (a wildcard)"


async def test_a_revoked_key_is_broken_and_raises_nothing_new(offline: httpx.AsyncClient) -> None:
    zone = m365()
    target = "selector1-example-test._domainkey.example.onmicrosoft.com"
    zone.alias("selector1._domainkey.example.test", target).add(target, "TXT", "v=DKIM1; p=")
    result = await mapped(zone, offline)
    dkim = item(result, "Microsoft 365", "dkim")
    assert (dkim.state, dkim.detail) == (
        State.BROKEN,
        "the only key found is revoked, dangling or malformed",
    )
    assert [e.name for e in dkim.evidence] == ["selector1._domainkey.example.test"]
    assert service(result, "Microsoft 365").setups[0].complete is False
    assert setup_findings(result) == []


async def test_a_malformed_record_at_a_current_selector_is_broken(
    offline: httpx.AsyncClient,
) -> None:
    zone = m365().add("selector1._domainkey.example.test", "TXT", "v=DKIM1; k=rsa")
    dkim = item(await mapped(zone, offline), "Microsoft 365", "dkim")
    assert dkim.state is State.BROKEN
    assert [str(e) for e in dkim.evidence] == [
        "selector1._domainkey.example.test TXT v=DKIM1; k=rsa"
    ]


async def test_a_key_at_an_older_selector_is_present_with_the_current_names(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().selectors_exist("example.test")
    zone.alias("k1._domainkey.example.test", "dkim.mcsv.net").add("dkim.mcsv.net", "TXT", KEY)
    result = await mapped(zone, offline)
    dkim = item(result, "Mailchimp", "dkim")
    assert (dkim.state, dkim.detail) == (
        State.PRESENT,
        "older setup: a key at k1; the current setup names k2",
    )
    assert service(result, "Mailchimp").setups[0].complete is True
    assert setup.line(service(result, "Mailchimp").setups[0]) == (
        "Setup at example.test: DKIM present (older setup: a key at k1; the current setup names "
        "k2), SPF not needed, bounce CNAME not needed."
    )


async def test_any_other_vendor_missing_a_required_record_is_a_warning(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("example.test", "TXT", "v=spf1 include:sendgrid.net -all")
    result = await mapped(zone.selectors_exist("example.test"), offline)
    assert states(result, "SendGrid") == {
        "dkim": "missing",
        "return_path": "missing",
        "spf": "not needed",
        "tracking": "missing",
    }
    # Only the required DKIM item raises anything; the optional CNAMEs are only shown.
    assert setup_findings(result) == [(Severity.WARNING, "SendGrid at example.test has no DKIM")]
    bounce = item(result, "SendGrid", "return_path")
    assert bounce.detail == "no CNAME into sendgrid.net at the 23 labels asked"
    assert len(bounce.evidence) == 23


async def test_a_mailbox_in_mx_on_a_subdomain_only_is_a_warning_not_a_risk(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("mail.example.test", "MX", "1 aspmx.l.google.com")
    zone.add("mail.example.test", "TXT", "v=spf1 include:_spf.google.com -all")
    result = await mapped(zone, offline)
    assert states(result, "Google Workspace", "mail.example.test")["dkim"] == "missing"
    assert setup_findings(result) == [
        (Severity.WARNING, "Google Workspace at mail.example.test has no DKIM")
    ]


async def test_an_account_only_service_is_one_note_and_nothing_about_its_setup(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().add("example.test", "TXT", "MS=ms12345678", "v=spf1 -all")
    result = await mapped(zone.selectors_exist("example.test"), offline)
    assert states(result, "Microsoft 365")["dkim"] == "missing"
    (note,) = [f for f in result.findings if f.title.startswith("Microsoft 365")]
    assert note.severity is Severity.NOTE
    assert note.title == "Microsoft 365 shows only an account at example.test"
    assert "Is the account still used?" in note.detail
    assert [str(e) for e in note.evidence] == ["example.test TXT MS=ms12345678"]


async def test_a_bounce_domain_is_the_return_path_of_the_setup_above_it(
    offline: httpx.AsyncClient,
) -> None:
    zone = Zone().selectors_exist("example.test")
    for n in (1, 2):
        target = f"s{n}.domainkey.u1.wl1.sendgrid.net"
        zone.alias(f"s{n}._domainkey.example.test", target).add(target, "TXT", KEY)
    zone.add("send.example.test", "MX", "10 mx.sendgrid.net")
    zone.add("send.example.test", "TXT", "v=spf1 include:sendgrid.net ~all")
    result = await mapped(zone, offline)
    setups = service(result, "SendGrid").setups
    assert [s.where for s in setups] == ["example.test"]  # send.example.test is no setup of its own
    bounce = item(result, "SendGrid", "return_path")
    assert bounce.state is State.PRESENT
    assert bounce.asked == "MX at send.example.test"
    assert [str(e) for e in bounce.evidence] == ["send.example.test MX 10 mx.sendgrid.net"]
    assert setups[0].complete is True
    assert setup_findings(result) == []


async def test_a_setup_asks_dns_nothing_more(
    offline: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_setups = m365()
    await mapped(with_setups, offline)
    without = m365()
    loaded = catalog.load()
    monkeypatch.setattr(catalog, "load", lambda: replace(loaded, setups={}))
    bare = await mapped(without, offline)
    assert service(bare, "Microsoft 365").setups == ()
    assert with_setups.asked == without.asked


async def test_json_carries_setups_under_each_service(offline: httpx.AsyncClient) -> None:
    result = await mapped(m365().add("example.test", "TXT", "amazonses:abcdefghijkl"), offline)
    data = json.loads(json.dumps(result.to_dict()))
    by_name = {s["name"]: s for s in data["services"]}
    (found,) = by_name["Microsoft 365"]["setups"]
    assert found["where"] == "example.test" and found["complete"] is False
    assert found["items"][1] == {
        "record": "dkim",
        "need": "required",
        "state": "missing",
        "evidence": [
            {
                "name": f"selector{n}._domainkey.example.test",
                "rtype": "TXT",
                "value": "no such name",
                "checked_at": CHECKED.isoformat(),
            }
            for n in (1, 2)
        ]
        + [
            {
                "name": "_domainkey.example.test",
                "rtype": "TXT",
                "value": "no record of this type",
                "checked_at": CHECKED.isoformat(),
            }
        ],
        "asked": "TXT at selector1._domainkey.example.test and TXT at "
        "selector2._domainkey.example.test",
        "detail": "no key at selector1._domainkey or selector2._domainkey, names that do not exist",
    }
    assert by_name["Amazon SES"]["setups"] == []  # no setup data for it yet


async def test_every_view_shows_the_setup_in_one_clause(offline: httpx.AsyncClient) -> None:
    result = await mapped(m365(), offline)
    # The missing key is the finding's; the clause says its state only.
    clause = "setup incomplete: DKIM missing"
    console = Console(record=True, width=400)
    text.render(result, console)
    shown = console.export_text()
    assert re.search(r"Setup +incomplete: DKIM missing *\n", shown)
    (row,) = [r for r in markdown.render(result).splitlines() if r.startswith("| Microsoft 365")]
    assert row.endswith(f"| {clause} |")
    # With evidence, every item, in the words setup.line uses.
    line = setup.line(service(result, "Microsoft 365").setups[0])
    full = markdown.render(result, evidence=True)
    assert "SPF present" in line and "SPF present" in full
    # The web page leads with the clause and keeps every item inside All records.
    page = html.html(result)
    card = page[page.index('id="service-microsoft-365"') :]
    card = card[: card.index("</article>")]
    assert card.index(f'<p class="meta setup">{clause}</p>') < card.index("All records")
    assert card.index("SPF present") > card.index("All records")


def _with_setup(vendor: str, *items: dict[str, Any]) -> dict[str, Any]:
    raw: dict[str, Any] = json.loads(
        (Path(catalog.__file__).parent / "data/vendors.json").read_text()
    )
    raw["vendors"][vendor]["setup"] = list(items)
    return raw


PAGE = {"domain": "microsoft.com", "record": "https://learn.microsoft.com/x", "date": "2026-10-11"}


@pytest.mark.parametrize(
    ("entry", "refused"),
    [
        ({"record": "spf", "need": "required", "values": ["_spf.google.com"]}, "not a pattern"),
        ({"record": "dkim", "need": "required", "values": ["k2"]}, "not a pattern"),
        ({"record": "bimi", "need": "required", "values": ["x"]}, "record is not one of"),
        ({"record": "spf", "need": "always", "values": ["x"]}, "need is not"),
        ({"record": "return_path", "need": "none", "values": ["x"]}, "names no values"),
        ({"record": "spf", "need": "required", "values": []}, "names its values"),
    ],
)
def test_loading_refuses_a_setup_item_that_breaks_a_rule(
    entry: dict[str, Any], refused: str
) -> None:
    with pytest.raises(ValueError, match=refused):
        catalog.build(_with_setup("Microsoft 365", {**entry, "proof": PAGE}))


def test_loading_refuses_a_setup_proof_that_is_not_an_https_page_of_its_domain() -> None:
    entry = {"record": "spf", "need": "required", "values": ["spf.protection.outlook.com"]}
    for record in ("http://learn.microsoft.com/x", "https://example.com/x", "microsoft.com"):
        proof = {**PAGE, "record": record}
        with pytest.raises(ValueError, match="is not an https URL on the domain"):
            catalog.build(_with_setup("Microsoft 365", {**entry, "proof": proof}))
    with pytest.raises(ValueError, match="no proof"):
        catalog.build(_with_setup("Microsoft 365", entry))


# The vendors whose setup the data carries: every mailbox and security gateway whose own docs
# a plain HTTP client can read, and the most seen senders across data/hunt_domains.txt.
WITH_SETUP = {
    "Microsoft 365",
    "Google Workspace",
    "Cloudflare Email Routing",
    "Fastmail",
    "GoDaddy Professional Email",
    "IONOS",
    "Proton Mail",
    "Rackspace Email",
    "Zoho Mail",
    "Barracuda",
    "DuoCircle",
    "Symantec MessageLabs",
    "Cloudflare Email Security",
    "Cisco Secure Email",
    "SendGrid",
    "Mailchimp",
    "Klaviyo",
    "Zendesk",
    "Mandrill",
    "Postmark",
    "Mailgun",
    "Intercom",
    "HubSpot",
    "Atlassian",
    "Marketo",
    "Campaign Monitor",
    "SparkPost",
    "Mailjet",
    "Customer.io",
    "Sailthru",
    "Trend Micro Email Security",
}
# Receivers with no setup, because no page on their own docs site names the values to a plain
# HTTP client: Mimecast's and Proofpoint's refuse it or need a login, and no Microsoft page names
# the consumer Outlook.com MX.
RECEIVERS_WITHOUT_DOCS = {"Mimecast", "Proofpoint", "Outlook.com (consumer)", "SiteGround"}


def test_the_vendors_carry_a_setup_backed_by_their_own_docs() -> None:
    loaded = catalog.load()
    assert set(loaded.setups) == WITH_SETUP
    for vendor, rules in loaded.setups.items():
        for rule in rules:
            assert rule.proof.record.startswith("https://"), (vendor, rule.record)
            assert (rule.need is Need.NONE) == (not rule.values), (vendor, rule.record)


def test_every_receiver_carries_a_setup_or_is_named_as_having_no_readable_docs() -> None:
    loaded = catalog.load()
    receivers = {
        name for name, block in loaded.services.items() if block["category"] in setup.RECEIVERS
    }
    assert receivers - set(loaded.setups) == RECEIVERS_WITHOUT_DOCS


async def test_a_likely_service_missing_spf_raises_a_note_not_a_warning(
    offline: httpx.AsyncClient,
) -> None:
    # A key named for Cloudflare Email Routing is all the map holds of it: likely, not sure.
    zone = m365(signed=True).add("cf2024-1._domainkey.example.test", "TXT", KEY)
    result = await mapped(zone, offline)
    assert service(result, "Cloudflare Email Routing").tier is Tier.LIKELY
    (finding,) = [f for f in result.findings if f.title.startswith("Cloudflare Email Routing")]
    assert finding.severity is Severity.NOTE and "only as likely" in finding.detail
