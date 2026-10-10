"""The whole map, end to end, on a fake domain."""

import pytest
from conftest import Zone

from sendermap import map_domain
from sendermap.engine import clean_domain
from sendermap.model import Role, Tier

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
