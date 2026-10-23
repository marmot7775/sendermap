"""A candidate that is a CNAME to the domain, as www.github.com is to github.com, answers with the
domain's SPF and MX: it is not a sending subdomain. An alias to a name outside the domain still
is, since its records are nowhere else in the map."""

import httpx
from conftest import CHECKED, Zone, context

from sendermap import map_domain
from sendermap.sources import subdomains

SPF = "v=spf1 include:spf.protection.outlook.com -all"
MX = "0 example-com.mail.protection.outlook.com"


def apex() -> Zone:
    return Zone().add("example.com", "TXT", SPF).add("example.com", "MX", MX)


async def test_an_alias_of_the_domain_is_not_a_sending_subdomain() -> None:
    zone = apex().alias("mail.example.com", "example.com")
    found = await subdomains.discover(context(zone), ())
    assert found.sending == ()


async def test_an_alias_of_another_candidate_is_not_a_sending_subdomain() -> None:
    zone = apex().add("email.example.com", "TXT", "v=spf1 include:mailgun.org ~all")
    zone.alias("mail.example.com", "email.example.com")
    found = await subdomains.discover(context(zone), ())
    assert found.sending == ("email.example.com",)


async def test_an_alias_to_a_name_outside_the_domain_still_sends() -> None:
    zone = apex().add("bounce.vendor.example", "MX", "10 feedback.vendor.example")
    zone.alias("bounce.example.com", "bounce.vendor.example")
    found = await subdomains.discover(context(zone), ())
    assert found.sending == ("bounce.example.com",)


async def test_an_alias_of_the_domain_adds_no_service_or_finding_there(
    offline: httpx.AsyncClient,
) -> None:
    zone = apex().alias("mail.example.com", "example.com")
    result = await map_domain(
        "example.com", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    assert "mail.example.com" not in result.subdomains_checked
    assert all("mail.example.com" not in f.title for f in result.findings)
    assert all(c.where != "mail.example.com" for s in result.services for c in s.claims)
