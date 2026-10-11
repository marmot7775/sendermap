"""The whole map, end to end, on a fake domain."""

from dataclasses import replace
from datetime import datetime

import httpx
import pytest
from conftest import CHECKED, Zone

from sendermap import catalog, engine, map_domain
from sendermap.engine import clean_domain
from sendermap.model import Role, SenderMap, Tier

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392


def reverse_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """Load the selector rules in reverse, so a rule moves up only if a hint moves it."""
    loaded = catalog.load()
    flipped = replace(loaded, rules=tuple(reversed(loaded.rules)))
    monkeypatch.setattr(catalog, "load", lambda: flipped)


def acme() -> Zone:
    return (
        Zone()
        .add("acme.test", "MX", "1 aspmx.l.google.com")
        .add(
            "acme.test",
            "TXT",
            "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all",
            "MS=ms12345678",
        )
        .add("_dmarc.acme.test", "TXT", "v=DMARC1; p=reject; rua=mailto:x@rua.agari.com")
        .add("google._domainkey.acme.test", "TXT", KEY)
        .alias("k2._domainkey.acme.test", "dkim2.mcsv.net")
        .add("dkim2.mcsv.net", "TXT", KEY)
        .alias("bounce.acme.test", "sparkpostmail.com")
        .add("email.acme.test", "TXT", "v=spf1 include:mailgun.org ~all")
        .add("email.acme.test", "MX", "10 mxa.mailgun.org")
    )


async def acme_map(http: httpx.AsyncClient) -> SenderMap:
    return await map_domain(
        "acme.test", checked_at=CHECKED, resolver=acme(), http=http, use_web=False
    )


async def test_the_map_ranks_every_service_by_its_strongest_evidence(
    offline: httpx.AsyncClient,
) -> None:
    result = await acme_map(offline)
    tiers = {s.name: s.tier for s in result.senders}
    assert tiers == {
        "Google Workspace": Tier.IN_USE,
        "Mailchimp": Tier.CONFIGURED,
        "SparkPost": Tier.CONFIGURED,
        "Mailgun": Tier.CONFIGURED,
        "Microsoft 365": Tier.ACCOUNT_ONLY,
    }
    assert [s.name for s in result.reporting] == ["Agari"]
    assert result.reporting[0].role is Role.REPORTING
    assert "email.acme.test" in result.subdomains_checked
    mailgun = next(s for s in result.senders if s.name == "Mailgun")
    assert mailgun.subdomains == ("email.acme.test",)


async def test_the_order_is_strongest_tier_first_and_reporting_last(
    offline: httpx.AsyncClient,
) -> None:
    result = await acme_map(offline)
    ranks = [s.tier.rank for s in result.senders if s.tier]
    assert len(ranks) == len(result.senders)
    assert ranks == sorted(ranks)
    assert result.services[-1].role is Role.REPORTING


async def test_the_result_serialises(offline: httpx.AsyncClient) -> None:
    result = await acme_map(offline)
    data = result.to_dict()
    assert data["schema"] == "sendermap/1" and data["domain"] == "acme.test"
    assert data["run"]["checked_at"] == "2026-10-09T12:00:00+00:00"
    assert data["run"]["lookups"] == result.run.lookups > 0


async def test_a_map_is_dated_by_its_caller_in_a_known_timezone(offline: httpx.AsyncClient) -> None:
    with pytest.raises(ValueError, match="timezone"):
        await map_domain("acme.test", checked_at=datetime(2026, 10, 9), resolver=acme())


async def test_mx_and_spf_hints_put_google_and_microsoft_selectors_first(
    offline: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Reversed, so Google and Microsoft start last and only their hints can move them up.
    reverse_rules(monkeypatch)
    zone = (
        Zone()
        .add("hinted.test", "MX", "1 smtp.google.com")
        .add("hinted.test", "TXT", "v=spf1 include:_spf.hinted.test ~all")
        .add("_spf.hinted.test", "TXT", "v=spf1 include:spf.protection.outlook.com ~all")
        .selectors_exist("hinted.test")
    )
    await map_domain("hinted.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False)
    probed = [
        name.removesuffix("._domainkey.hinted.test")
        for name, rtype in zone.asked
        if rtype == "TXT" and name.endswith("._domainkey.hinted.test")
    ][1:]  # the first is the wildcard canary
    assert set(probed[:4]) == {"gapps", "google", "selector1", "selector2"}
    # The full sweep, each name once.
    assert len(probed) == len(set(probed)) == len(catalog.load().probe_selectors)


@pytest.mark.parametrize(
    ("pasted", "domain"),
    [
        ("Example.COM.", "example.com"),
        ("https://www.example.com/pricing?x=1", "example.com"),
        ("neil@example.com", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_a_domain_is_accepted_however_it_is_pasted(pasted: str, domain: str) -> None:
    assert clean_domain(pasted) == domain


@pytest.mark.parametrize("bad", ["", "localhost", "not a domain"])
def test_nonsense_is_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        clean_domain(bad)


async def test_a_subdomain_whose_mx_is_google_probes_google_before_any_other_rule(
    offline: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Reversed, so Google starts last and only the subdomain's own MX can move it up.
    reverse_rules(monkeypatch)
    zone = (
        Zone()
        .add("mail.subhint.test", "MX", "1 smtp.google.com")
        .add("mail.subhint.test", "TXT", "v=spf1 include:hubspotemail.net ~all")
        .selectors_exist("mail.subhint.test")
    )
    await map_domain("subhint.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False)
    probed = [
        name.removesuffix("._domainkey.mail.subhint.test")
        for name, rtype in zone.asked
        if rtype == "TXT" and name.endswith("._domainkey.mail.subhint.test")
    ][1:]  # the first is the wildcard canary
    assert set(probed[:2]) == {"gapps", "google"}
    # The budget, then the names the HubSpot include backs that the budget left out.
    assert set(probed[engine.SUBDOMAIN_PROBES :]) == {"hs1", "hs2"}


async def test_every_piece_of_evidence_carries_the_runs_date(offline: httpx.AsyncClient) -> None:
    result = await acme_map(offline)
    evidence = [c.evidence for s in result.services for c in s.claims]
    evidence += [e for f in result.findings for e in f.evidence]
    assert evidence and {e.checked_at for e in evidence} == {result.run.checked_at}
