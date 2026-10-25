"""An MX host no pattern names, credited by the network its address is in."""

from conftest import Zone, context
from test_networks import owner

from sendermap.model import Kind, Severity
from sendermap.sources import mx

HOST = "o1.sendgrid.acme.test"  # SendGrid's reverse DNS shape, as investorpass.com publishes it


def sendgrid_mx(where: str = "acme.test") -> Zone:
    zone = Zone().add(where, "MX", f"1 {HOST}").add(HOST, "A", "167.89.106.132")
    return owner(zone, "167.89.106.132", "AS11377", "SENDGRID - SendGrid, Inc., US")


async def test_an_mx_host_in_a_services_own_network_is_that_service() -> None:
    observed = await mx.collect(context(sendgrid_mx(), "acme.test"), "acme.test")
    assert [(c.service, c.kind, c.where) for c in observed.claims] == [
        ("SendGrid", Kind.MX_ADDRESS, "acme.test")
    ]
    assert observed.unknowns == ()
    (claim,) = observed.claims
    assert str(claim.evidence) == f"acme.test MX 1 {HOST}"
    assert claim.supporting[0].value == "167.89.106.132"
    assert any("cymru" in e.name for e in claim.supporting)


async def test_the_domains_mx_at_a_sending_address_is_a_warning() -> None:
    observed = await mx.collect(context(sendgrid_mx(), "acme.test"), "acme.test")
    (finding,) = observed.findings
    assert finding.severity is Severity.WARNING
    assert finding.title == "The MX at acme.test points at a SendGrid sending address"
    assert "167.89.106.132" in finding.detail and "Check that mail" in finding.detail


async def test_a_subdomains_mx_at_a_sending_address_raises_no_finding() -> None:
    observed = await mx.collect(
        context(sendgrid_mx("send.acme.test"), "acme.test"), "send.acme.test"
    )
    assert [c.service for c in observed.claims] == ["SendGrid"]
    assert observed.findings == ()


async def test_an_mx_host_on_a_cloud_stays_unknown() -> None:
    zone = Zone().add("acme.test", "MX", "10 mail.acme.test").add("mail.acme.test", "A", "3.5.1.1")
    owner(zone, "3.5.1.1", "AS16509", "AMAZON-02 - Amazon.com, Inc., US")
    observed = await mx.collect(context(zone, "acme.test"), "acme.test")
    assert observed.claims == () and observed.findings == ()
    assert [u.value for u in observed.unknowns] == ["mail.acme.test"]


async def test_an_mx_host_whose_lookup_fails_stays_unknown() -> None:
    zone = Zone(failing={HOST}).add("acme.test", "MX", f"1 {HOST}")
    observed = await mx.collect(context(zone, "acme.test"), "acme.test")
    assert observed.claims == ()
    assert [u.value for u in observed.unknowns] == [HOST]


async def test_an_mx_address_that_is_not_an_address_is_skipped() -> None:
    zone = sendgrid_mx().add(HOST, "A", "0.bogus")  # answers are sorted, so this comes first
    observed = await mx.collect(context(zone, "acme.test"), "acme.test")
    assert [c.service for c in observed.claims] == ["SendGrid"]
