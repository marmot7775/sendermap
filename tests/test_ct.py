"""Certificate transparency: names from a recorded crt.sh answer, resolved against a fake zone.

tests/fixtures/crtsh_allbirds.json is a slice of crt.sh's real answer for %.allbirds.com,
recorded on 2026-10-09. The DNS answers here are made up; no test reaches the network.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone, context

from sendermap import map_domain
from sendermap.cli import _parser
from sendermap.model import CertificateEvidence, CtStatus, CtSummary, Kind, Observed, Tier
from sendermap.render import markdown
from sendermap.sources import Context, ct

RECORDED = json.loads((Path(__file__).parent / "fixtures" / "crtsh_allbirds.json").read_text())
DOMAIN = "allbirds.com"


def zone() -> Zone:
    return (
        Zone()
        .alias("links.mail.allbirds.com", "e.customeriomail.com")
        .add("e.customeriomail.com", "A", "192.0.2.10")
        .alias("app-email.allbirds.com", "u123.sparkpostmail.com")  # dangling: no longer there
        .add("accounts.allbirds.com", "MX", "10 mxa.mailgun.org")
        .add("dev.api.allbirds.com", "A", "198.2.128.7")
        .add("7.128.2.198.origin.asn.cymru.com", "TXT", "14782 | 198.2.128.0/24 | US | arin")
        .add("AS14782.asn.cymru.com", "TXT", "14782 | US | arin | 2005 | MAILCHIMP - Mailchimp")
        .add("test.api.allbirds.com", "A", "203.0.113.5")  # resolves, names no service
        .alias("gift-cards.middle-tier-prod.aws.allbirds.com", "u161779.wl030.sendgrid.net")
        .add("u161779.wl030.sendgrid.net", "A", "192.0.2.20")
    )


class CrtSh:
    """A crt.sh that answers with `body` after failing `failures` times, counting requests."""

    def __init__(self, body: list[dict[str, Any]] = RECORDED, failures: int = 0) -> None:
        self.body, self.failures = body, failures
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != "crt.sh":
            raise AssertionError(f"test tried to reach {request.url}")
        self.requests.append(request)
        if len(self.requests) <= self.failures:
            raise httpx.ReadTimeout("crt.sh timed out", request=request)
        return httpx.Response(200, json=self.body)


async def run(
    crtsh: CrtSh, cache: Path | None, at: datetime = CHECKED, dns: Zone | None = None
) -> tuple[Observed, CtSummary]:
    async with httpx.AsyncClient(transport=httpx.MockTransport(crtsh)) as http:
        ctx = context(dns or zone(), DOMAIN)
        ctx = Context(ctx.domain, ctx.dns, ctx.catalog, at, http)
        return await ct.collect(ctx, cache)


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ct, "BACKOFF", 0.0)


def test_names_are_split_lowercased_and_cleaned() -> None:
    extra = [
        {
            "name_value": "LINKS.MAIL.ALLBIRDS.COM",
            "not_before": "2020-01-01",
            "not_after": "2020-02-01",
        },
        {
            "name_value": "allbirds.com.evil.example\nnotallbirds.com",
            "not_before": "",
            "not_after": "",
        },
    ]
    names = ct.logged_names(RECORDED + extra, DOMAIN)
    assert [n.name for n in names] == [
        "2a57j78d05nkylnjxxxbsfyb1hqpih3.gift-cards.middle-tier-prod.aws.allbirds.com",
        "accounts.allbirds.com",
        "app-email.allbirds.com",
        "dev.api.allbirds.com",
        "gift-cards.middle-tier-prod.aws.allbirds.com",
        "links.mail.allbirds.com",
        "middle-tier-dev.aws.allbirds.com",
        "middle-tier-prod.aws.allbirds.com",
        "test.api.allbirds.com",
    ]
    links = next(n for n in names if n.name == "links.mail.allbirds.com")
    assert (links.not_before, links.not_after) == ("2025-12-07T00:00:00", "2027-01-05T23:59:59")


async def test_the_query_is_for_every_name_under_the_domain_url_encoded(tmp_path: Path) -> None:
    crtsh = CrtSh()
    await run(crtsh, tmp_path)
    (request,) = crtsh.requests
    assert request.url.params["q"] == "%.allbirds.com"
    assert "q=%25.allbirds.com" in str(request.url) and request.url.params["output"] == "json"


async def test_logged_names_go_through_the_dns_matchers_with_certificate_evidence(
    tmp_path: Path,
) -> None:
    observed, summary = await run(CrtSh(), tmp_path)
    claims = {(c.service, c.kind, c.where): c.evidence for c in observed.claims}
    assert set(claims) == {
        ("Customer.io", Kind.TRACKING, "links.mail.allbirds.com"),
        ("Mailgun", Kind.SUBDOMAIN_MX, "accounts.allbirds.com"),
        ("Mailchimp", Kind.CT_ADDRESS, "dev.api.allbirds.com"),
        ("Klaviyo", Kind.CT_CNAME, "gift-cards.middle-tier-prod.aws.allbirds.com"),
    }
    assert all(isinstance(e, CertificateEvidence) for e in claims.values())
    links = claims[("Customer.io", Kind.TRACKING, "links.mail.allbirds.com")]
    assert isinstance(links, CertificateEvidence)
    assert links.name == "links.mail.allbirds.com" and links.rtype == "certificate"
    assert (links.not_before, links.not_after) == ("2025-12-07T00:00:00", "2027-01-05T23:59:59")
    assert links.target == "e.customeriomail.com"
    assert summary.status is CtStatus.READ and summary.logged == summary.resolved == 9


async def test_a_logged_name_that_no_longer_resolves_is_a_possible_past_vendor(
    tmp_path: Path,
) -> None:
    observed, summary = await run(CrtSh(), tmp_path)
    (past,) = observed.historical
    assert past.service == "SparkPost" and past.evidence.name == "app-email.allbirds.com"
    assert past.evidence.not_after == "2020-12-10T23:33:19"
    assert "SparkPost" not in {c.service for c in observed.claims}
    # The other gift-cards name and the middle-tier names do not resolve and name no service.
    assert summary.gone_unnamed == 3


async def test_a_logged_autodiscover_cname_is_an_account_trace_as_in_the_dns_path(
    tmp_path: Path,
) -> None:
    logged = [
        {"name_value": "autodiscover.allbirds.com", "not_before": "2012", "not_after": "2015"}
    ]
    dns = Zone().alias("autodiscover.allbirds.com", "autodiscover.outlook.com")
    dns.add("autodiscover.outlook.com", "A", "192.0.2.30")
    observed, _ = await run(CrtSh(logged), tmp_path, dns=dns)
    (claim,) = observed.claims
    assert (claim.service, claim.kind) == ("Microsoft 365", Kind.AUTODISCOVER)
    assert claim.kind.tier is Tier.ACCOUNT_ONLY


async def test_crt_sh_is_retried_twice_then_answers(tmp_path: Path) -> None:
    crtsh = CrtSh(failures=2)
    _, summary = await run(crtsh, tmp_path)
    assert len(crtsh.requests) == 3 and summary.status is CtStatus.READ


async def test_crt_sh_failing_three_times_marks_ct_unavailable_and_the_map_finishes(
    offline: httpx.AsyncClient,
) -> None:
    crtsh = CrtSh(failures=3)
    async with httpx.AsyncClient(transport=httpx.MockTransport(crtsh)) as http:
        result = await map_domain(
            DOMAIN,
            checked_at=CHECKED,
            resolver=zone(),
            http=http,
            use_web=False,
            use_subdomains=False,
            use_ct=True,
        )
    assert len(crtsh.requests) == 3
    assert result.ct.status is CtStatus.UNAVAILABLE
    (gap,) = [g for g in result.gaps if g.asked.startswith("certificate transparency")]
    assert gap.happened == "unavailable after 3 tries: failed: ReadTimeout"
    assert "crt.sh was unavailable" in markdown.render(result)


async def test_answers_are_cached_on_disk_for_a_day(tmp_path: Path) -> None:
    await run(CrtSh(), tmp_path)
    assert (tmp_path / "allbirds.com.json").exists()
    refuses = CrtSh(failures=99)
    observed, summary = await run(refuses, tmp_path, at=CHECKED + timedelta(hours=23))
    assert refuses.requests == [] and summary.status is CtStatus.CACHED
    assert {c.service for c in observed.claims} == {
        "Customer.io",
        "Mailgun",
        "Mailchimp",
        "Klaviyo",
    }
    again = CrtSh()
    _, summary = await run(again, tmp_path, at=CHECKED + timedelta(hours=25))
    assert len(again.requests) == 1 and summary.status is CtStatus.READ


async def test_ct_is_off_unless_asked_for(offline: httpx.AsyncClient) -> None:
    # The offline client fails the test on any request to crt.sh.
    result = await map_domain(DOMAIN, checked_at=CHECKED, resolver=zone(), http=offline)
    assert result.ct.status is CtStatus.OFF and result.historical == ()
    assert not _parser().parse_args(["allbirds.com"]).ct
    assert _parser().parse_args(["allbirds.com", "--ct"]).ct


async def test_the_map_and_its_markdown_carry_the_ct_section(tmp_path: Path) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(CrtSh())) as http:
        result = await map_domain(
            DOMAIN,
            checked_at=CHECKED,
            resolver=zone(),
            http=http,
            use_web=False,
            use_subdomains=False,
            use_ct=True,
            ct_cache=tmp_path,
        )
    tracking = next(s for s in result.senders if s.name == "Customer.io")
    assert tracking.tier is Tier.CONFIGURED
    page = markdown.render(result)
    assert "## Certificate transparency" in page
    assert "Possible past vendor: SparkPost at app-email.allbirds.com" in page
    assert result.to_dict()["historical"][0]["evidence"]["not_after"] == "2020-12-10T23:33:19"
