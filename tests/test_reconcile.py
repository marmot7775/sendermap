"""The claimed list against the map: names matched exactly after normalising, four parts, every
surface, and a client's words never dropped."""

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone
from rich.console import Console

from sendermap import catalog, cli, map_domain
from sendermap.catalog import normalise
from sendermap.model import (
    Claim,
    Evidence,
    Kind,
    Reconciled,
    Reconciliation,
    Role,
    Run,
    SenderMap,
    Service,
    Tier,
)
from sendermap.reconcile import reconcile, split, with_claimed
from sendermap.render import CLAIMED_PARTS, html, markdown, text

DOMAIN = "acme.test"


def service(name: str, tier: Tier | None, kind: Kind, value: str) -> Service:
    evidence = Evidence(DOMAIN, "TXT", value, CHECKED)
    role = Role.REPORTING if tier is None else Role.SENDER
    return Service(
        name, catalog.load().category(name), tier, role, (Claim(name, kind, DOMAIN, evidence),)
    )


def fake_map() -> SenderMap:
    return SenderMap(
        domain=DOMAIN,
        services=(
            service(
                "Microsoft 365", Tier.IN_USE, Kind.MX, "0 acme-test.mail.protection.outlook.com"
            ),
            service(
                "Mailchimp", Tier.CONFIGURED, Kind.SPF_INCLUDE, "v=spf1 include:servers.mcsv.net"
            ),
            service("Shopify", Tier.LIKELY, Kind.WEBSITE, "cdn.shopify.com"),
            service("Agari", None, Kind.DMARC_REPORTS, "v=DMARC1; rua=mailto:x@rua.agari.com"),
        ),
        run=Run(CHECKED, 0.0, 0, "fake zone"),
    )


CLAIMED = ["Office 365", "O365", "mailchimp", "Klaviyo", "our CRM"]


# ------------------------------------------------------------------ the normaliser


@pytest.mark.parametrize(
    ("typed", "normal"),
    [
        ("Mailchimp", "mailchimp"),
        ("  MAILCHIMP  ", "mailchimp"),
        ("Mail Chimp", "mailchimp"),
        ("The Mailchimp Company", "mailchimpcompany"),
        ("Mailchimp, Inc.", "mailchimp"),
        ("Mailchimp LLC", "mailchimp"),
        ("Mailchimp Ltd", "mailchimp"),
        ("the Klaviyo, inc", "klaviyo"),
        ("Customer.io", "customerio"),
        ("Help-Scout", "helpscout"),
        ("Office_365", "office365"),
        ("STRASSE", "strasse"),
        ("Straße", "strasse"),  # casefold, not lower
    ],
)
def test_names_normalise_by_case_spaces_punctuation_and_company_words(
    typed: str, normal: str
) -> None:
    assert normalise(typed) == normal


def test_a_company_word_alone_is_still_a_name() -> None:
    # "The" or "Inc" with nothing else is what was typed, not something to drop.
    assert normalise("The") == "the"
    assert normalise("Inc.") == "inc"
    assert normalise("The Inc") == "inc"
    assert normalise(" ,. ") == ""


def test_matching_is_exact_after_normalising_never_fuzzy() -> None:
    loaded = catalog.load()
    assert loaded.named("mail chimp, inc.") == "Mailchimp"
    assert loaded.named("Mailchimps") is None
    assert loaded.named("Mailchim") is None
    assert loaded.named("Microsoft") is None
    assert loaded.named("Outlook") is None


# ------------------------------------------------------------------ aliases


@pytest.mark.parametrize(
    ("alias", "vendor"),
    [
        ("Office 365", "Microsoft 365"),
        ("O365", "Microsoft 365"),
        ("Exchange Online", "Microsoft 365"),
        ("Outlook for Microsoft 365", "Microsoft 365"),
        ("G Suite", "Google Workspace"),
        ("GSuite", "Google Workspace"),
        ("Gmail", "Google Workspace"),
        ("Google", "Google Workspace"),
        ("Twilio SendGrid", "SendGrid"),
        ("Intuit Mailchimp", "Mailchimp"),
        ("Sendinblue", "Brevo"),
        ("ConvertKit", "Kit"),
        ("Pardot", "Salesforce Account Engagement"),
        ("Hotmail", "Outlook.com (consumer)"),
    ],
)
def test_aliases_load_and_name_their_vendor(alias: str, vendor: str) -> None:
    assert catalog.load().named(alias) == vendor


def test_every_vendor_is_named_by_its_own_name() -> None:
    loaded = catalog.load()
    assert all(loaded.named(name) == name for name in loaded.services)


def test_aliases_are_plain_names_with_no_proof() -> None:
    raw = json.loads((Path(catalog.__file__).parent / "data" / "vendors.json").read_text())
    for block in raw["vendors"].values():
        assert all(isinstance(a, str) for a in block.get("aliases", []))


def _raw(**aliases: list[Any]) -> dict[str, Any]:
    raw: dict[str, Any] = json.loads(
        (Path(catalog.__file__).parent / "data" / "vendors.json").read_text()
    )
    for vendor, names in aliases.items():
        raw["vendors"][vendor.replace("_", " ")]["aliases"] = names
    return raw


@pytest.mark.parametrize(
    ("aliases", "says"),
    [
        ({"Zoho_Mail": ["Office 365"]}, "already names Microsoft 365"),
        ({"Zoho_Mail": ["mail chimp"]}, "already names Mailchimp"),
        ({"Klaviyo": ["klaviyo inc"]}, "already names Klaviyo"),
        ({"Klaviyo": ["..."]}, "not a name"),
        ({"Klaviyo": [365]}, "not a name"),
        ({"Klaviyo": "Klav"}, "not a list"),
    ],
)
def test_loading_refuses_an_alias_that_is_empty_or_names_two_vendors(
    aliases: dict[str, Any], says: str
) -> None:
    with pytest.raises(ValueError, match=says):
        catalog.build(_raw(**aliases))


# ------------------------------------------------------------------ the four parts


def test_the_four_parts_on_a_fake_map() -> None:
    got = reconcile(fake_map(), CLAIMED, catalog.load())
    assert got == Reconciliation(
        confirmed=(
            Reconciled("Microsoft 365", Tier.IN_USE, ("Office 365", "O365")),
            Reconciled("Mailchimp", Tier.CONFIGURED, ("mailchimp",)),
        ),
        unclaimed=(Reconciled("Shopify", Tier.LIKELY),),
        unfound=(Reconciled("Klaviyo", None, ("Klaviyo",)),),
        unknown=("our CRM",),
    )


def test_a_reporting_service_is_never_unclaimed_but_can_be_confirmed() -> None:
    unclaimed = reconcile(fake_map(), ["Shopify"], catalog.load())
    assert "Agari" not in {r.service for r in unclaimed.unclaimed}
    confirmed = reconcile(fake_map(), ["Agari"], catalog.load())
    assert confirmed.confirmed == (Reconciled("Agari", None, ("Agari",)),)


def test_a_clients_words_are_kept_as_written() -> None:
    got = reconcile(fake_map(), ["  our CRM ", "Our CRM", "our CRM", "", "  "], catalog.load())
    assert got.unknown == ("our CRM", "Our CRM")
    assert got.confirmed == got.unfound == ()


def test_nothing_claimed_is_no_reconciliation() -> None:
    mapped = fake_map()
    assert with_claimed(mapped, [], catalog.load()).reconciliation is None
    assert with_claimed(mapped, [" ", ""], catalog.load()).reconciliation is None
    assert with_claimed(mapped, split(" , ,"), catalog.load()).reconciliation is None


def test_split_takes_a_comma_separated_list() -> None:
    assert split("Office 365, Mailchimp,,Klaviyo , our CRM") == [
        "Office 365",
        "Mailchimp",
        "Klaviyo",
        "our CRM",
    ]


# ------------------------------------------------------------------ the library and JSON


async def test_map_domain_takes_a_claimed_sequence(offline: httpx.AsyncClient) -> None:
    zone = (
        Zone()
        .add(DOMAIN, "MX", "10 aspmx.l.google.com")
        .add(DOMAIN, "TXT", "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all")
    )
    args: dict[str, Any] = {"checked_at": CHECKED, "http": offline, "use_web": False}
    plain = await map_domain(DOMAIN, resolver=zone, **args)
    asked = list(zone.asked)
    claimed = await map_domain(DOMAIN, resolver=zone, claimed=["G Suite", "Postmark"], **args)
    assert sorted(zone.asked[len(asked) :]) == sorted(asked)  # claiming asks nothing more
    assert plain.reconciliation is None
    assert claimed.reconciliation == Reconciliation(
        confirmed=(Reconciled("Google Workspace", Tier.IN_USE, ("G Suite",)),),
        unclaimed=(Reconciled("Mailchimp", Tier.CONFIGURED),),
        unfound=(Reconciled("Postmark", None, ("Postmark",)),),
    )


def test_json_carries_the_reconciliation_or_null() -> None:
    assert fake_map().to_dict()["reconciliation"] is None
    data = json.loads(json.dumps(with_claimed(fake_map(), CLAIMED, catalog.load()).to_dict()))
    assert data["reconciliation"] == {
        "confirmed": [
            {
                "service": "Microsoft 365",
                "tier": "In use",
                "claimed_as": ["Office 365", "O365"],
            },
            {"service": "Mailchimp", "tier": "Configured", "claimed_as": ["mailchimp"]},
        ],
        "unclaimed": [{"service": "Shopify", "tier": "Likely", "claimed_as": []}],
        "unfound": [{"service": "Klaviyo", "tier": None, "claimed_as": ["Klaviyo"]}],
        "unknown": ["our CRM"],
    }


# ------------------------------------------------------------------ the command line


@pytest.fixture
def mapped(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The CLI with map_domain replaced by the fake map, reconciled as the engine does."""
    seen: dict[str, Any] = {}

    async def fake(domain: str, **kwargs: Any) -> SenderMap:
        seen.update(kwargs)
        return with_claimed(fake_map(), kwargs.get("claimed", ()), catalog.load())

    monkeypatch.setattr(cli, "map_domain", fake)
    return seen


def test_the_cli_takes_claimed(mapped: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([DOMAIN, "--json", "--claimed", ", ".join(CLAIMED)]) == 0
    assert mapped["claimed"] == CLAIMED
    data = json.loads(capsys.readouterr().out)
    assert data["reconciliation"]["unknown"] == ["our CRM"]


def test_the_cli_takes_a_claimed_file_one_name_per_line(
    mapped: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listed = tmp_path / "claimed.txt"
    listed.write_text("Office 365\n\nAcme, the CRM we built\n  Klaviyo  \n", encoding="utf-8")
    argv = [DOMAIN, "--json", "--claimed", "Mailchimp", "--claimed-file", str(listed)]
    assert cli.main(argv) == 0
    assert mapped["claimed"] == ["Mailchimp", "Office 365", "Acme, the CRM we built", "Klaviyo"]
    data = json.loads(capsys.readouterr().out)
    assert data["reconciliation"]["unknown"] == ["Acme, the CRM we built"]


def test_the_cli_without_claimed_gives_null(
    mapped: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main([DOMAIN, "--json"]) == 0
    assert mapped["claimed"] == []
    assert json.loads(capsys.readouterr().out)["reconciliation"] is None


def test_the_cli_says_when_the_claimed_file_cannot_be_read(
    mapped: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main([DOMAIN, "--claimed-file", str(tmp_path / "missing.txt")]) == 2
    assert "cannot read" in capsys.readouterr().err
    assert mapped == {}


# ------------------------------------------------------------------ the views

PARTS = [
    ("Claimed and found", 'Microsoft 365, In use (claimed as "Office 365", "O365")'),
    ("Claimed and found", 'Mailchimp, Configured (claimed as "mailchimp")'),
    ("Found, not claimed", "Shopify, Likely"),
    ("Claimed, not found at any name checked", "Klaviyo"),
    ("Claimed, no service Sendermap knows by that name", "our CRM"),
]


def test_the_text_view_shows_claimed_senders_in_four_parts() -> None:
    console = Console(record=True, width=200)
    text.render(with_claimed(fake_map(), CLAIMED, catalog.load()), console)
    shown = console.export_text()
    assert "Your list against the map" in shown
    section = shown.split("Your list against the map")[1]
    for heading, line in PARTS:
        assert f"  {heading}\n" in section
        assert f"    {line}\n" in section
    assert "Agari" not in section


def test_the_text_view_says_none_for_an_empty_part() -> None:
    console = Console(record=True, width=200)
    text.render(with_claimed(fake_map(), ["Shopify"], catalog.load()), console)
    section = console.export_text().split("Your list against the map")[1]
    assert "  Claimed, not found at any name checked\n    none\n" in section


def test_the_markdown_view_shows_claimed_senders() -> None:
    shown = markdown.render(with_claimed(fake_map(), CLAIMED, catalog.load()))
    section = shown.split("## Your list against the map\n")[1]
    for heading, line in PARTS:
        assert f"- **{heading}**" in section
        assert f"  - {line}" in section


def test_no_view_shows_the_section_when_nothing_was_claimed() -> None:
    console = Console(record=True, width=200)
    text.render(fake_map(), console)
    assert "Your list against the map" not in console.export_text()
    assert "Your list against the map" not in markdown.render(fake_map())


def test_the_web_page_uses_the_same_words_and_passes_claimed_on() -> None:
    page = html.html(with_claimed(fake_map(), CLAIMED, catalog.load()))
    for _, heading in CLAIMED_PARTS:
        assert f"<h4>{heading}</h4>" in page
    js = (Path(text.__file__).parent.parent / "web" / "static" / "app.js").read_text()
    assert "&claimed=" in js


# ------------------------------------------------------------------ the HTTP API


async def test_the_api_takes_claimed_and_keeps_the_cached_map_clean() -> None:
    pytest.importorskip("fastapi")
    from sendermap.web import app as site  # noqa: PLC0415

    site.state.cache[DOMAIN] = (time.monotonic(), fake_map())
    site.state.seen.clear()
    transport = httpx.ASGITransport(app=site.app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://site") as client:
            query = {"d": DOMAIN, "claimed": ", ".join(CLAIMED)}
            claimed = (await client.get("/api/map", params=query)).json()
            plain = (await client.get("/api/map", params={"d": DOMAIN})).json()
            md = (await client.get("/api/map.md", params=query)).text
    finally:
        site.state.cache.pop(DOMAIN, None)
        site.state.seen.clear()
    assert claimed["reconciliation"]["unfound"][0]["service"] == "Klaviyo"
    assert plain["reconciliation"] is None
    assert "## Your list against the map" in md
