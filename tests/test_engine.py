"""The whole map, end to end, on a fake domain."""

import pytest
from conftest import Zone

from sendermap import engine, map_domain
from sendermap.engine import clean_domain
from sendermap.model import Role, Tier
from sendermap.selectors import load_rules

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392


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


async def test_the_map_ranks_every_service_by_its_strongest_evidence(offline):
    result = await map_domain("acme.test", resolver=acme(), http=offline, use_web=False)
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


async def test_the_order_is_strongest_tier_first_and_reporting_last(offline):
    result = await map_domain("acme.test", resolver=acme(), http=offline, use_web=False)
    ranks = [s.tier.rank for s in result.senders]
    assert ranks == sorted(ranks)
    assert result.services[-1].role is Role.REPORTING


async def test_the_result_serialises(offline):
    result = await map_domain("acme.test", resolver=acme(), http=offline, use_web=False)
    data = result.to_dict()
    assert data["schema"] == "sendermap/1" and data["domain"] == "acme.test"


async def test_mx_and_spf_hints_put_google_and_microsoft_selectors_first(offline, monkeypatch):
    # Reversed, so Google and Microsoft start last and only their hints can move them up.
    monkeypatch.setattr(engine, "load_rules", lambda: tuple(reversed(load_rules())))
    zone = (
        Zone()
        .add("hinted.test", "MX", "1 smtp.google.com")
        .add("hinted.test", "TXT", "v=spf1 include:_spf.hinted.test ~all")
        .add("_spf.hinted.test", "TXT", "v=spf1 include:spf.protection.outlook.com ~all")
    )
    await map_domain("hinted.test", resolver=zone, http=offline, use_web=False)
    probed = [
        name.removesuffix("._domainkey.hinted.test")
        for name, rtype in zone.asked
        if rtype == "TXT" and name.endswith("._domainkey.hinted.test")
    ][1:]  # the first is the wildcard canary
    assert set(probed[:3]) == {"google", "selector1", "selector2"}
    assert len(probed) == len(set(probed)) > 100  # the full sweep, each name once


@pytest.mark.parametrize(
    ("pasted", "domain"),
    [
        ("Example.COM.", "example.com"),
        ("https://www.example.com/pricing?x=1", "example.com"),
        ("neil@example.com", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_a_domain_is_accepted_however_it_is_pasted(pasted, domain):
    assert clean_domain(pasted) == domain


@pytest.mark.parametrize("bad", ["", "localhost", "not a domain"])
def test_nonsense_is_refused(bad):
    with pytest.raises(ValueError):
        clean_domain(bad)


async def test_a_subdomain_whose_mx_is_google_probes_google_before_any_other_rule(
    offline, monkeypatch
):
    # Reversed, so Google starts last and only the subdomain's own MX can move it up.
    monkeypatch.setattr(engine, "load_rules", lambda: tuple(reversed(load_rules())))
    zone = Zone().add("mail.subhint.test", "MX", "1 smtp.google.com")
    await map_domain("subhint.test", resolver=zone, http=offline, use_web=False)
    probed = [
        name.removesuffix("._domainkey.mail.subhint.test")
        for name, rtype in zone.asked
        if rtype == "TXT" and name.endswith("._domainkey.mail.subhint.test")
    ][1:]  # the first is the wildcard canary
    assert probed[0] == "google"
    # The budget, then the names the Google MX backs that the budget left out.
    assert set(probed[engine.SUBDOMAIN_PROBES :]) == {"ga1", "gapps", "googlemail"}
