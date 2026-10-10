"""Rule 3: a question that got no answer is a gap that says what was asked and what happened,
never silence and never an absence."""

import httpx
import pytest
from conftest import CHECKED, Zone, context

from sendermap import engine, map_domain
from sendermap.model import Evidence
from sendermap.sources import (
    CANARY,
    Context,
    dkim,
    labels,
    mta_sts,
    networks,
    reports,
    subdomains,
    web,
)

EV = Evidence("example.com", "TXT", "ip4:...", CHECKED)


def asked(observed) -> dict[str, str]:
    return {g.asked: g.happened for g in observed.gaps}


def with_http(zone: Zone, handler) -> tuple[Context, httpx.AsyncClient]:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = context(zone)
    return Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http), http


async def test_a_failed_dmarc_or_tls_rpt_lookup_is_a_gap():
    zone = Zone(failing={"_dmarc.example.com", "_smtp._tls.example.com"})
    assert asked(await reports.collect(context(zone))) == {
        "DMARC: TXT at _dmarc.example.com": "lookup failed",
        "TLS-RPT: TXT at _smtp._tls.example.com": "lookup failed",
    }


async def test_a_missing_dmarc_record_is_an_absence_not_a_gap():
    assert (await reports.collect(context(Zone()))).gaps == ()


async def test_failed_label_lookups_and_a_failed_wildcard_check_are_gaps():
    zone = Zone(failing={f"{CANARY}.example.com", "bounce.example.com"})
    gaps = asked(await labels.collect(context(zone), "example.com"))
    assert gaps["bounce and tracking CNAMEs: CNAME at bounce.example.com"] == "lookup failed"
    assert gaps[f"wildcard check: CNAME at {CANARY}.example.com"].startswith("lookup failed")


async def test_a_failed_dkim_wildcard_check_is_a_gap():
    zone = Zone(failing={f"{CANARY}._domainkey.example.com"})
    observed = await dkim.collect(context(zone), "example.com", ["k1"], {})
    assert f"wildcard check: TXT at {CANARY}._domainkey.example.com" in asked(observed)


async def test_an_mta_sts_policy_that_does_not_load_is_a_gap():
    zone = Zone().add("_mta-sts.example.com", "TXT", "v=STSv1; id=1")
    ctx, http = with_http(zone, lambda request: httpx.Response(404))
    async with http:
        gaps = asked(await mta_sts.collect(ctx))
    assert gaps == {
        "MTA-STS policy: GET https://mta-sts.example.com/.well-known/mta-sts.txt": "HTTP 404"
    }


async def test_an_mta_sts_policy_not_fetched_for_want_of_a_web_client_is_a_gap():
    zone = Zone().add("_mta-sts.example.com", "TXT", "v=STSv1; id=1")
    (gap,) = (await mta_sts.collect(context(zone))).gaps
    assert gap.happened.startswith("not fetched")


async def test_a_failed_mta_sts_record_lookup_is_a_gap():
    zone = Zone(failing={"_mta-sts.example.com"})
    assert asked(await mta_sts.collect(context(zone))) == {
        "MTA-STS: TXT at _mta-sts.example.com": "lookup failed"
    }


async def test_a_subprocessor_page_that_does_not_load_is_a_gap():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            html = '<a href="/legal/subprocessors">Subprocessors</a>'
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        return httpx.Response(500)

    ctx, http = with_http(Zone(), handler)
    async with http:
        gaps = asked(await web.collect(ctx))
    assert gaps == {
        "the subprocessor page: GET https://example.com/legal/subprocessors": "HTTP 500"
    }


async def test_a_subdomain_whose_lookups_failed_is_a_gap_not_a_non_sender(offline):
    zone = Zone(failing={"email.example.com"})
    ctx = context(zone)
    ctx = Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, offline)
    found = await subdomains.discover(ctx)
    assert "email.example.com" not in found.sending
    (gap,) = found.gaps
    assert "email.example.com" in gap.asked and gap.happened.startswith("lookup failed")


async def test_a_failed_network_lookup_is_not_read_as_no_network():
    failed = Zone(failing={"1.100.51.198.origin.asn.cymru.com"})
    observed = await networks.collect(context(failed), "example.com", [("198.51.100.0/24", EV)])
    assert observed.unknowns[0].value == "198.51.100.0/24 (network lookup failed)"
    assert asked(observed) == {
        "network owners: Team Cymru TXT for 198.51.100.0/24": "lookup failed"
    }
    unannounced = await networks.collect(context(Zone()), "example.com", [("198.51.100.0/24", EV)])
    assert unannounced.unknowns[0].value == "198.51.100.0/24 (no one network announces it)"
    assert unannounced.gaps == ()


async def test_a_failed_apex_txt_lookup_says_spf_and_tokens_were_not_checked(offline):
    zone = Zone(failing={"acme.test"})
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    gaps = asked(result)
    assert gaps["SPF: TXT at acme.test"] == "lookup failed"
    assert gaps["verification tokens: TXT at acme.test"] == "lookup failed"


async def test_a_crash_in_the_subdomain_search_is_reported_as_a_crash(offline, monkeypatch):
    async def crash(ctx):
        raise KeyError("wordlist")

    monkeypatch.setattr(engine.subdomains, "discover", crash)
    result = await map_domain("acme.test", checked_at=CHECKED, resolver=Zone(), http=offline)
    assert asked(result)["sending subdomains"] == "the search crashed: KeyError"
    assert not any("certificate" in g.asked for g in result.gaps)


@pytest.mark.parametrize(
    ("use_web", "use_subdomains", "expected"),
    [
        (False, True, {"the website"}),
        (True, False, {"sending subdomains"}),
        (False, False, {"the website", "sending subdomains", "MTA-STS policy"}),
    ],
)
async def test_turning_a_check_off_is_a_gap(offline, use_web, use_subdomains, expected):
    zone = Zone().add("_mta-sts.acme.test", "TXT", "v=STSv1; id=1")

    def no_policy(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.certspotter.com":
            return httpx.Response(200, json=[])
        if request.url.host == "mta-sts.acme.test":
            return httpx.Response(200, text="version: STSv1\nmode: testing\n")
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(no_policy)) as http:
        result = await map_domain(
            "acme.test",
            checked_at=CHECKED,
            resolver=zone,
            http=http,
            use_web=use_web,
            use_subdomains=use_subdomains,
        )
    named = {g.asked.split(":")[0] for g in result.gaps}
    assert expected <= named
    if use_web:
        assert "the website" not in {g.asked for g in result.gaps}
