"""Certificate transparency: names from a recorded crt.sh answer and Cert Spotter answers,
read once per map and resolved against a fake zone.

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
from sendermap.model import (
    CertificateEvidence,
    CtProvider,
    CtStatus,
    CtSummary,
    Kind,
    Observed,
    SenderMap,
    Tier,
)
from sendermap.render import ct_lines, markdown
from sendermap.render.view import view
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


class Logs:
    """Both certificate log providers: crt.sh answers with `body` after failing `failures` times,
    Cert Spotter with `issuances` after failing `spotter_failures` times. Every request is kept."""

    def __init__(
        self,
        body: list[dict[str, Any]] = RECORDED,
        failures: int = 0,
        issuances: list[dict[str, Any]] | None = None,
        spotter_failures: int = 0,
    ) -> None:
        self.body, self.failures = body, failures
        self.issuances, self.spotter_failures = issuances or [], spotter_failures
        self.requests: list[httpx.Request] = []

    def asked(self, host: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host not in ("crt.sh", "api.certspotter.com"):
            raise AssertionError(f"test tried to reach {request.url}")
        self.requests.append(request)
        if request.url.host == "api.certspotter.com":
            if len(self.asked("api.certspotter.com")) <= self.spotter_failures:
                raise httpx.ReadTimeout("Cert Spotter timed out", request=request)
            return httpx.Response(200, json=self.issuances)
        if len(self.asked("crt.sh")) <= self.failures:
            raise httpx.ReadTimeout("crt.sh timed out", request=request)
        return httpx.Response(200, json=self.body)


async def run(
    logs: Logs, cache: Path | None, at: datetime = CHECKED, dns: Zone | None = None
) -> tuple[Observed, CtSummary]:
    async with httpx.AsyncClient(transport=httpx.MockTransport(logs)) as http:
        ctx = context(dns or zone(), DOMAIN)
        ctx = Context(ctx.domain, ctx.dns, ctx.catalog, at, http)
        read = await ct.read_logs(ctx, cache, expired=True)
        observed, summary = await ct.collect(ctx, read)
        return read.observed + observed, summary


async def map_with(logs: Logs, *, use_subdomains: bool, use_ct: bool) -> SenderMap:
    async with httpx.AsyncClient(transport=httpx.MockTransport(logs)) as http:
        return await map_domain(
            DOMAIN,
            checked_at=CHECKED,
            resolver=zone(),
            http=http,
            use_web=False,
            use_subdomains=use_subdomains,
            use_ct=use_ct,
        )


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
    names = ct.logged_names(ct.CRT_SH.rows(RECORDED + extra), DOMAIN)
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
    logs = Logs()
    await run(logs, tmp_path)
    (request,) = logs.asked("crt.sh")
    assert request.url.params["q"] == "%.allbirds.com"
    assert "q=%25.allbirds.com" in str(request.url) and request.url.params["output"] == "json"


async def test_logged_names_go_through_the_dns_matchers_with_certificate_evidence(
    tmp_path: Path,
) -> None:
    observed, summary = await run(Logs(), tmp_path)
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
    assert summary.providers == (
        CtProvider("Cert Spotter", CtStatus.READ, 0),
        CtProvider("crt.sh", CtStatus.READ, 9),
    )


async def test_a_logged_name_that_no_longer_resolves_is_a_possible_past_vendor(
    tmp_path: Path,
) -> None:
    observed, summary = await run(Logs(), tmp_path)
    (past,) = observed.historical
    assert past.service == "SparkPost" and past.evidence.name == "app-email.allbirds.com"
    assert past.evidence.not_after == "2020-12-10T23:33:19"
    assert "SparkPost" not in {c.service for c in observed.claims}
    # The other gift-cards name and middle-tier-dev do not resolve and name no service;
    # middle-tier-prod has a name below it, so it exists (an empty non-terminal, RFC 8020).
    assert summary.gone_unnamed == 2


async def test_a_logged_autodiscover_cname_is_an_account_trace_as_in_the_dns_path(
    tmp_path: Path,
) -> None:
    logged = [
        {"name_value": "autodiscover.allbirds.com", "not_before": "2012", "not_after": "2015"}
    ]
    dns = Zone().alias("autodiscover.allbirds.com", "autodiscover.outlook.com")
    dns.add("autodiscover.outlook.com", "A", "192.0.2.30")
    observed, _ = await run(Logs(logged), tmp_path, dns=dns)
    (claim,) = observed.claims
    assert (claim.service, claim.kind) == ("Microsoft 365", Kind.AUTODISCOVER)
    assert claim.kind.tier is Tier.ACCOUNT_ONLY


async def test_crt_sh_is_retried_twice_then_answers(tmp_path: Path) -> None:
    logs = Logs(failures=2)
    _, summary = await run(logs, tmp_path)
    assert len(logs.asked("crt.sh")) == 3 and summary.status is CtStatus.READ


async def test_crt_sh_failing_three_times_is_a_gap_and_the_names_from_cert_spotter_are_read(
    tmp_path: Path,
) -> None:
    issuances = [{"dns_names": ["links.mail.allbirds.com"], "not_after": "2027-01-05T23:59:59Z"}]
    logs = Logs(failures=3, issuances=issuances)
    observed, summary = await run(logs, tmp_path)
    assert len(logs.asked("crt.sh")) == 3
    (gap,) = observed.gaps
    assert (
        gap.asked
        == "certificate transparency, crt.sh: GET https://crt.sh/?q=%25.allbirds.com&output=json"
    )
    assert gap.happened == "unavailable after 3 tries: failed: ReadTimeout"
    assert summary.status is CtStatus.READ and summary.resolved == 1
    assert [p.status for p in summary.providers] == [CtStatus.READ, CtStatus.UNAVAILABLE]
    assert {c.service for c in observed.claims} == {"Customer.io"}


async def test_no_provider_answering_marks_ct_unavailable_and_the_map_finishes() -> None:
    logs = Logs(failures=3, spotter_failures=1)
    result = await map_with(logs, use_subdomains=True, use_ct=True)
    assert len(logs.asked("crt.sh")) == 3 and len(logs.asked("api.certspotter.com")) == 1
    assert result.ct.status is CtStatus.UNAVAILABLE
    gaps = {g.asked.split(":")[0]: g.happened for g in result.gaps}
    assert (
        gaps["certificate transparency, crt.sh"] == "unavailable after 3 tries: failed: ReadTimeout"
    )
    assert gaps["certificate transparency, Cert Spotter"] == (
        "unavailable after 1 try: failed: ReadTimeout"
    )
    assert "No certificate log answered" in markdown.render(result)


async def test_the_logs_are_read_once_per_map_for_the_subdomains_and_the_ct_pass() -> None:
    issuances = [{"dns_names": ["accounts.allbirds.com"]}]
    logs = Logs(issuances=issuances)
    result = await map_with(logs, use_subdomains=True, use_ct=True)
    assert len(logs.asked("api.certspotter.com")) == 1 and len(logs.asked("crt.sh")) == 1
    # A name only crt.sh logged is a subdomain candidate too: accounts publishes MX.
    assert "accounts.allbirds.com" in result.subdomains_checked
    assert result.ct.logged == 9


async def test_without_ct_only_cert_spotter_is_asked_and_crt_sh_is_an_off_gap() -> None:
    logs = Logs(issuances=[{"dns_names": ["accounts.allbirds.com", "*.mail.allbirds.com"]}])
    result = await map_with(logs, use_subdomains=True, use_ct=False)
    assert logs.asked("crt.sh") == [] and len(logs.asked("api.certspotter.com")) == 1
    assert result.ct.status is CtStatus.OFF and result.historical == ()
    assert result.ct.providers == (
        CtProvider("Cert Spotter", CtStatus.READ, 2),
        CtProvider("crt.sh", CtStatus.OFF, 0),
    )
    (off,) = [g for g in result.gaps if "crt.sh" in g.asked]
    assert off.happened == "not asked: read only with --ct (it also holds expired certificates)"
    assert "accounts.allbirds.com" in result.subdomains_checked
    assert ct_lines(result) == []


async def test_with_both_checks_off_no_log_is_asked() -> None:
    logs = Logs()
    result = await map_with(logs, use_subdomains=False, use_ct=False)
    assert logs.requests == [] and result.ct == CtSummary()
    assert not any(g.asked.startswith("certificate transparency") for g in result.gaps)


def test_both_providers_rows_go_through_one_parse_and_the_latest_certificate_wins() -> None:
    spotter = ct.CERT_SPOTTER.rows(
        [
            {
                "dns_names": ["*.Links.Mail.allbirds.com", "allbirds.com"],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-06-01T00:00:00Z",
            },
            "not an issuance",
        ]
    )
    names = ct.logged_names(spotter + ct.CRT_SH.rows(RECORDED), DOMAIN)
    links = next(n for n in names if n.name == "links.mail.allbirds.com")
    assert (links.not_before, links.not_after) == ("2026-01-01T00:00:00", "2027-06-01T00:00:00")
    assert len(names) == 9
    assert [n.name for n in names] == sorted(n.name for n in names)


async def test_answers_are_cached_on_disk_for_a_day_per_provider(tmp_path: Path) -> None:
    await run(Logs(), tmp_path)
    assert (tmp_path / "crtsh" / "allbirds.com.json").exists()
    assert (tmp_path / "certspotter" / "allbirds.com.json").exists()
    refuses = Logs(failures=99, spotter_failures=99)
    observed, summary = await run(refuses, tmp_path, at=CHECKED + timedelta(hours=23))
    assert refuses.requests == []
    assert [p.status for p in summary.providers] == [CtStatus.CACHED, CtStatus.CACHED]
    assert {c.service for c in observed.claims} == {
        "Customer.io",
        "Mailgun",
        "Mailchimp",
        "Klaviyo",
    }
    again = Logs()
    _, summary = await run(again, tmp_path, at=CHECKED + timedelta(hours=25))
    assert len(again.requests) == 2
    assert [p.status for p in summary.providers] == [CtStatus.READ, CtStatus.READ]


def test_the_cache_directory_is_ct(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert ct.default_cache() == tmp_path / "sendermap" / "ct"


async def test_ct_is_off_unless_asked_for(offline: httpx.AsyncClient) -> None:
    # The offline client answers Cert Spotter and fails the test on any request to crt.sh.
    result = await map_domain(DOMAIN, checked_at=CHECKED, resolver=zone(), http=offline)
    assert result.ct.status is CtStatus.OFF and result.historical == ()
    assert not _parser().parse_args(["allbirds.com"]).ct
    assert _parser().parse_args(["allbirds.com", "--ct"]).ct
    assert "crt.sh" in _parser().format_help()


async def test_the_map_and_its_markdown_carry_the_ct_section(tmp_path: Path) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(Logs())) as http:
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
    assert "## Certificate logs" in page
    assert "9 names logged (Cert Spotter read, 0 names; crt.sh read, 9 names)" in page
    assert "Possible past vendor: SparkPost at app-email.allbirds.com" in page
    assert result.to_dict()["historical"][0]["evidence"]["not_after"] == "2020-12-10T23:33:19"
    assert result.to_dict()["ct"]["providers"][1] == {
        "name": "crt.sh",
        "status": "read",
        "logged": 9,
    }


async def test_a_cached_answer_dated_without_a_zone_is_fetched_again(tmp_path: Path) -> None:
    # A cache written by hand or by an older build: comparing it with the map's aware time
    # raised TypeError instead of counting as no cache.
    for key in ("crtsh", "certspotter"):
        (tmp_path / key).mkdir()
        stored = {"fetched_at": "2026-10-09T11:00:00", "rows": []}
        (tmp_path / key / f"{DOMAIN}.json").write_text(json.dumps(stored))
    logs = Logs()
    _, summary = await run(logs, tmp_path)
    assert len(logs.requests) == 2
    assert [p.status for p in summary.providers] == [CtStatus.READ, CtStatus.READ]


@pytest.mark.parametrize(
    ("answer", "said"),
    [
        (httpx.Response(200, text="<html>busy</html>"), "the answer was not JSON"),
        (
            httpx.Response(200, json={"error": "rate limited"}),
            "the answer was not a list of certificates",
        ),
    ],
)
async def test_an_answer_that_is_not_a_list_of_certificates_is_a_gap(
    answer: httpx.Response, said: str
) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: answer)) as http:
        fetched = await ct._fetch(http, ct.CRT_SH, DOMAIN)
    assert fetched == f"unavailable after {ct.CRT_SH.tries} tries: {said}"


async def test_no_web_client_fetches_nothing() -> None:
    assert await ct._fetch(None, ct.CRT_SH, DOMAIN) == "not fetched: no web client"


def logged(name: str) -> Logs:
    return Logs(body=[{"name_value": name, "not_before": "2026-01-01", "not_after": "2027-01-01"}])


async def test_a_logged_name_in_a_range_one_service_publishes_is_credited_to_it() -> None:
    dns = (
        Zone()
        .add("amazonses.com", "TXT", "v=spf1 ip4:198.51.100.0/24 -all")
        .add("ses.allbirds.com", "A", "198.51.100.9", "0.bogus")  # sorted first
    )
    observed, _ = await run(logged("ses.allbirds.com"), None, dns=dns)
    (claim,) = observed.claims
    assert (claim.service, claim.kind, claim.where) == (
        "Amazon SES",
        Kind.CT_ADDRESS,
        "ses.allbirds.com",
    )
    assert claim.evidence.value.startswith("A 198.51.100.9; named in a certificate")
    assert [s.value for s in claim.supporting] == ["ip4:198.51.100.0/24"]


async def test_the_map_names_the_mx_host_a_logged_name_points_at(tmp_path: Path) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(Logs())) as http:
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
    mailgun = next(s for s in view(result, evidence=False).services if s.name == "Mailgun")
    # The summary was the certificate's last date, "2027-01-01", the last word of its value.
    assert [k.summary for k in mailgun.kinds] == ["mxa.mailgun.org"]


async def test_a_cache_that_cannot_be_written_is_skipped(tmp_path: Path) -> None:
    blocked = tmp_path / "cache"
    blocked.write_text("a file where the directory would go")
    logs = Logs()
    _, summary = await run(logs, blocked)
    assert [p.status for p in summary.providers] == [CtStatus.READ, CtStatus.READ]
