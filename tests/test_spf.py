"""The SPF walk: only authorizing links count, and the tree is read the way receivers read it."""

from conftest import Zone, context

from sendermap.model import Kind, Observed, Severity
from sendermap.sources import spf


async def walk(zone: Zone, domain: str = "example.com") -> tuple[Observed, spf.SpfTree]:
    observed, tree = await spf.collect(context(zone, domain), domain)
    return observed, tree


def services(observed: Observed) -> set[str]:
    return {c.service for c in observed.claims if c.kind is Kind.SPF_INCLUDE}


async def test_bare_and_plus_includes_count_others_do_not() -> None:
    zone = Zone().add(
        "example.com",
        "TXT",
        "v=spf1 include:sendgrid.net +include:mailgun.org -include:servers.mcsv.net "
        "~include:spf.mtasv.net ?include:amazonses.com ~all",
    )
    observed, _ = await walk(zone)
    assert services(observed) == {"SendGrid", "Mailgun"}


async def test_nothing_after_all_is_read() -> None:
    zone = Zone().add("example.com", "TXT", "v=spf1 -all include:sendgrid.net")
    observed, _ = await walk(zone)
    assert services(observed) == set()


async def test_a_redirect_counts_unless_the_record_has_all() -> None:
    with_redirect = Zone().add("example.com", "TXT", "v=spf1 redirect=_spf.google.com")
    observed, _ = await walk(with_redirect)
    assert services(observed) == {"Google Workspace"}
    ignored = Zone().add("example.com", "TXT", "v=spf1 -all redirect=_spf.google.com")
    observed, _ = await walk(ignored)
    assert services(observed) == set()


async def test_a_wrapper_of_the_domains_own_is_followed() -> None:
    zone = (
        Zone()
        .add("example.com", "TXT", "v=spf1 include:_spf.example.com -all")
        .add("_spf.example.com", "TXT", "v=spf1 include:sendgrid.net ip4:192.0.2.0/24 -all")
    )
    observed, tree = await walk(zone)
    assert services(observed) == {"SendGrid"}
    assert [r for r, _ in tree.ranges] == ["192.0.2.0/24"]
    assert observed.unknowns == ()


async def test_inside_a_services_record_nothing_more_is_credited() -> None:
    # An ESP whose own record includes Amazon SES is that ESP, not an SES account.
    zone = (
        Zone()
        .add("example.com", "TXT", "v=spf1 include:sendgrid.net -all")
        .add("sendgrid.net", "TXT", "v=spf1 include:amazonses.com ip4:198.51.100.0/24 -all")
    )
    observed, tree = await walk(zone)
    assert services(observed) == {"SendGrid"}
    assert tree.ranges == []


async def test_a_flattening_service_speaks_for_the_domain() -> None:
    # allbirds.com: EasyDMARC copies the domain's senders into its own record.
    zone = (
        Zone()
        .add("example.com", "TXT", "v=spf1 include:_spf.example_com._d.easydmarc.pro -all")
        .add(
            "_spf.example_com._d.easydmarc.pro",
            "TXT",
            "v=spf1 include:mailgun.org ip4:192.0.2.0/24 -all",
        )
    )
    observed, tree = await walk(zone)
    assert services(observed) == {"Mailgun"}
    assert [r for r, _ in tree.ranges] == ["192.0.2.0/24"]
    assert tree.hosted_by == "EasyDMARC"
    assert any("managed through EasyDMARC" in f.title for f in observed.findings)


async def test_a_macro_record_is_noted_not_followed() -> None:
    # glossier.com publishes only a Valimail macro include.
    zone = Zone().add(
        "example.com", "TXT", "v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all"
    )
    observed, tree = await walk(zone)
    assert tree.hosted_by == "Valimail"
    assert observed.claims == ()
    assert any("Valimail" in f.title for f in observed.findings)


async def test_an_unknown_include_is_listed() -> None:
    zone = Zone().add("example.com", "TXT", "v=spf1 include:_spf.sendergen.com -all")
    observed, _ = await walk(zone)
    assert [u.value for u in observed.unknowns] == ["_spf.sendergen.com"]


async def test_more_than_ten_lookups_is_a_risk() -> None:
    includes = " ".join(f"include:s{i}.example.net" for i in range(11))
    zone = Zone().add("example.com", "TXT", f"v=spf1 {includes} -all")
    observed, tree = await walk(zone)
    assert tree.lookups == 11
    assert any(
        f.severity is Severity.RISK and "11 DNS lookups" in f.title for f in observed.findings
    )


async def test_two_records_authorize_nothing() -> None:
    zone = Zone().add("example.com", "TXT", "v=spf1 include:sendgrid.net -all", "v=spf1 -all")
    observed, _ = await walk(zone)
    assert observed.claims == ()
    assert observed.findings[0].severity is Severity.RISK


async def test_plus_all_is_a_risk() -> None:
    zone = Zone().add("example.com", "TXT", "v=spf1 +all")
    observed, _ = await walk(zone)
    assert any("every server" in f.title for f in observed.findings)


async def test_a_failed_lookup_is_a_gap_not_an_absence() -> None:
    zone = Zone(failing={"example.com"})
    observed, _ = await walk(zone)
    assert observed.gaps and observed.claims == ()


async def test_a_repeated_include_counts_its_lookups_each_time_as_receivers_do() -> None:
    zone = (
        Zone()
        .add("example.com", "TXT", "v=spf1 include:_a.example.com include:_b.example.com -all")
        .add("_a.example.com", "TXT", "v=spf1 include:_c.example.com -all")
        .add("_b.example.com", "TXT", "v=spf1 include:_c.example.com -all")
        .add("_c.example.com", "TXT", "v=spf1 include:x1.example.net include:x2.example.net -all")
    )
    ctx = context(zone)
    _, tree = await spf.collect(ctx, "example.com")
    # _a, _c, x1, x2, then _b, and _c with x1 and x2 again.
    assert tree.lookups == 8
    asked = [name for name, _ in zone.asked]
    assert len(asked) == len(set(asked)), "a record was asked twice"


async def test_an_include_loop_is_a_risk() -> None:
    zone = (
        Zone()
        .add("example.com", "TXT", "v=spf1 include:_a.example.com -all")
        .add("_a.example.com", "TXT", "v=spf1 include:example.com -all")
    )
    observed, _ = await walk(zone)
    (loop,) = [f for f in observed.findings if "inside itself" in f.title]
    assert loop.severity is Severity.RISK
    assert loop.evidence[0].value == "include:example.com"
