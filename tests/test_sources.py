"""MX, labels, tokens, report addresses and the website."""

import httpx
import pytest
from conftest import Zone, context

from sendermap.dns import Answer, Status
from sendermap.model import Kind
from sendermap.sources import Context, labels, mx, reports, tokens, web


async def test_a_mailbox_host_is_in_use_and_a_senders_subdomain_mx_is_not() -> None:
    zone = (
        Zone()
        .add("example.com", "MX", "0 example-com.mail.protection.outlook.com")
        .add("email.example.com", "MX", "10 mxa.mailgun.org")
    )
    ctx = context(zone)
    apex = await mx.collect(ctx, "example.com")
    sub = await mx.collect(ctx, "email.example.com")
    assert [(c.service, c.kind) for c in apex.claims] == [("Microsoft 365", Kind.MX)]
    assert [(c.service, c.kind) for c in sub.claims] == [("Mailgun", Kind.SUBDOMAIN_MX)]


async def test_a_null_mx_says_the_domain_takes_no_mail() -> None:
    observed = await mx.collect(context(Zone().add("example.com", "MX", "0 .")), "example.com")
    assert observed.claims == () and "accepts no mail" in observed.findings[0].title


async def test_bounce_and_tracking_cnames_name_the_services_they_point_at() -> None:
    zone = (
        Zone()
        .alias("bounce.example.com", "sparkpostmail.com")
        .alias("links.example.com", "e.customeriomail.com")
    )
    observed = await labels.collect(context(zone), "example.com")
    assert {(c.service, c.kind) for c in observed.claims} == {
        ("SparkPost", Kind.RETURN_PATH),
        ("Customer.io", Kind.TRACKING),
    }


async def test_a_wildcard_cname_is_not_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    zone = Zone()

    async def every_name_aliases(name: str, rtype: str) -> Answer:
        return Answer(name, rtype, Status.OK, ("sendgrid.net",), ("sendgrid.net",))

    monkeypatch.setattr(zone, "query", every_name_aliases)
    observed = await labels.collect(context(zone), "example.com")
    assert observed.claims == ()


async def test_tokens_are_account_traces() -> None:
    zone = Zone().add("example.com", "TXT", "MS=ms12345678", "google-site-verification=abc")
    observed = await tokens.collect(context(zone))
    assert [(c.service, c.kind) for c in observed.claims] == [("Microsoft 365", Kind.TOKEN)]


def test_report_addresses_parse_like_receivers_do() -> None:
    record = (
        "v=DMARC1; p=reject; rua=mailto:a@rua.agari.com!10m,mailto:b@example.com?x=y, "
        "MAILTO:c@ag.dmarcian.com; ruf=mailto:d@two@bad.com"
    )
    assert reports.report_domains(record, ("rua", "ruf")) == [
        "rua.agari.com",
        "example.com",
        "ag.dmarcian.com",
    ]


async def test_report_services_are_reporting_and_others_listed() -> None:
    zone = (
        Zone()
        .add(
            "_dmarc.example.com",
            "TXT",
            "v=DMARC1; p=none; rua=mailto:x@rua.agari.com,mailto:y@reports.example.net",
        )
        .add("_smtp._tls.example.com", "TXT", "v=TLSRPTv1; rua=mailto:z@uriports.com")
    )
    observed = await reports.collect(context(zone))
    assert {(c.service, c.kind) for c in observed.claims} == {
        ("Agari", Kind.DMARC_REPORTS),
        ("URIports", Kind.TLSRPT_REPORTS),
    }
    assert [(u.what, u.value) for u in observed.unknowns] == [
        ("DMARC reports go to", "reports.example.net")
    ]


async def test_the_website_names_its_scripts_and_subprocessors() -> None:
    pages = {
        "https://example.com/": '<script src="https://static.klaviyo.com/onsite/js/x.js"></script>'
        '<a href="/legal/subprocessors">Subprocessors</a>',
        "https://example.com/legal/subprocessors": "<td>SendGrid</td><td>Kit</td><td>Zendesk</td>",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = pages.get(str(request.url))
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        ctx = context(Zone())
        ctx = Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http)
        observed = await web.collect(ctx)
    assert {(c.service, c.kind, c.evidence.value) for c in observed.claims} == {
        ("Klaviyo", Kind.WEBSITE, "loads static.klaviyo.com"),
        ("SendGrid", Kind.SUBPROCESSOR, "names SendGrid"),
        ("Zendesk", Kind.SUBPROCESSOR, "names Zendesk"),
    }


async def test_a_link_form_or_text_on_the_website_is_a_mention_not_a_load() -> None:
    html = (
        '<link rel="stylesheet" href="//static.zdassets.com/x.css">'
        '<a href="https://www.klaviyo.com/">x</a> <script>var s="https://static.klaviyo.com"</script>'
        '<a href="https://cdn.shopify.com/s/files/terms.pdf">Terms</a>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        ctx = context(Zone())
        ctx = Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http)
        observed = await web.collect(ctx)
    assert {(c.service, c.kind, c.evidence.value) for c in observed.claims} == {
        ("Zendesk", Kind.WEBSITE, "loads static.zdassets.com"),
        ("Klaviyo", Kind.WEBSITE_MENTION, "mentions static.klaviyo.com"),
        ("Shopify", Kind.WEBSITE_MENTION, "mentions cdn.shopify.com"),
    }
