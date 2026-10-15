"""A zone with a wildcard answers every name, as shopify.com and gov.uk do: a label that gives
the wildcard's answer is not a sending subdomain, and one with records of its own still is."""

from conftest import Zone, context

from sendermap.sources import subdomains

WILDCARD_SPF = "v=spf1 ?all"
CHECK = f"{subdomains.WILDCARD_CHECK}.example.com"


def wildcard_zone(*labels: str) -> Zone:
    """The wildcard's answer at the check name and at every label given, as a zone with
    *.example.com gives it."""
    zone = Zone().add(CHECK, "TXT", WILDCARD_SPF)
    for label in labels:
        zone.add(f"{label}.example.com", "TXT", WILDCARD_SPF)
    return zone


async def test_a_label_that_gives_the_wildcards_spf_is_not_a_sending_subdomain() -> None:
    found = await subdomains.discover(context(wildcard_zone("mail", "email", "bounce")), ())
    assert found.sending == () and found.gaps == ()


async def test_a_label_with_spf_of_its_own_under_a_wildcard_still_sends() -> None:
    zone = wildcard_zone("mail").add("email.example.com", "TXT", "v=spf1 include:mailgun.org ~all")
    found = await subdomains.discover(context(zone), ())
    assert found.sending == ("email.example.com",)


async def test_a_label_with_the_wildcards_mx_is_not_a_sending_subdomain() -> None:
    zone = (
        Zone()
        .add(CHECK, "MX", "10 mx.host.example")
        .add("mail.example.com", "MX", "10 mx.host.example")
    )
    zone.add("email.example.com", "MX", "10 mxa.mailgun.org")
    found = await subdomains.discover(context(zone), ())
    assert found.sending == ("email.example.com",)


async def test_without_a_wildcard_a_label_with_spf_sends() -> None:
    zone = Zone().add("mail.example.com", "TXT", WILDCARD_SPF)
    found = await subdomains.discover(context(zone), ())
    assert found.sending == ("mail.example.com",)
