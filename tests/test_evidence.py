"""Rule 1: every claim and every finding on a mapped domain carries the evidence that shows it."""

import httpx
from conftest import CHECKED, Zone

from sendermap import map_domain
from sendermap.model import Kind

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392
SHORT_KEY = (  # a 512-bit RSA key
    "v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMXJ+Eb9M7cAUU0kfMbYcGXKIOj0UiC8bJhUqrzBcqMY"
    "a2XgMUmgWULrSfTMNR4YAxqWI2mPBrHdDivf0zMkYN8CAwEAAQ=="
)
HOME = (
    '<script src="https://static.klaviyo.com/onsite/js/klaviyo.js"></script>'
    '<form action="https://acme.us1.list-manage.com/subscribe/post"></form>'
    '<a href="/legal/subprocessors">Subprocessors</a>'
)
PAGES = {
    "https://mapped.test/": HOME,
    "https://mapped.test/legal/subprocessors": "<td>Zendesk</td><td>Postmark</td>",
}
LOGGED = [  # what crt.sh answers for %.mapped.test
    {"name_value": n, "not_before": "2026-01-01T00:00:00", "not_after": "2026-12-31T00:00:00"}
    for n in ("trk.mapped.test", "email.mapped.test", "www.mapped.test", "old.mapped.test")
]
POLICY = "version: STSv1\nmode: enforce\nmx: *.mail.protection.outlook.com\nmax_age: 86400\n"


def mapped() -> Zone:
    """Every source finds something, and most kinds of finding fire."""
    return (
        Zone()
        .add("mapped.test", "MX", "10 us-smtp-inbound-1.mimecast.com")
        .add(
            "mapped.test",
            "TXT",
            "v=spf1 include:_spf.google.com include:_loop.mapped.test ip4:198.51.100.0/24 "
            "include:unknown.example.net include:_spf.easydmarc.com +all",
            "MS=ms12345678",
        )
        .add("_loop.mapped.test", "TXT", "v=spf1 include:mapped.test -all")
        .add("_dmarc.mapped.test", "TXT", "v=DMARC1; p=none; rua=mailto:x@rua.agari.com")
        .add("_smtp._tls.mapped.test", "TXT", "v=TLSRPTv1; rua=mailto:t@uriports.com")
        .add("_mta-sts.mapped.test", "TXT", "v=STSv1; id=20261009")
        .add("google._domainkey.mapped.test", "TXT", KEY)
        .add("default._domainkey.mapped.test", "TXT", KEY)
        .add("mandrill._domainkey.mapped.test", "TXT", "v=DKIM1; p=")
        .add("k3._domainkey.mapped.test", "TXT", "v=DKIM1; k=rsa; ap=x")
        .add("s1._domainkey.mapped.test", "TXT", SHORT_KEY)
        .alias("k2._domainkey.mapped.test", "dkim2.mcsv.net")
        .add("dkim2.mcsv.net", "TXT", KEY)
        .alias("s2._domainkey.mapped.test", "s2.domainkey.u1.wl1.sendgrid.net")
        .add("_spf.easydmarc.com", "TXT", "v=spf1 include:sendgrid.net -all")
        .alias("bounce.mapped.test", "sparkpostmail.com")
        .alias("links.mapped.test", "links.iterable.com")
        .alias("autodiscover.mapped.test", "autodiscover.outlook.com")
        .add("email.mapped.test", "TXT", "v=spf1 include:mailgun.org ~all")
        .add("email.mapped.test", "MX", "10 mxa.mailgun.org")
        .add("corp.mapped.test", "MX", "1 smtp.google.com")
        .add("*._domainkey.corp.mapped.test", "TXT", KEY)
        .add("mail.mapped.test", "TXT", "v=spf1 include:sendgrid.net -all", "v=spf1 -all")
        .add("1.100.51.198.origin.asn.cymru.com", "TXT", "14782 | 198.51.100.0/24 | US | arin")
        .add("AS14782.asn.cymru.com", "TXT", "14782 | US | arin | 2005 | MAILCHIMP - Mailchimp")
        .add("www.mapped.test", "A", "198.51.100.1")
        .alias("trk.mapped.test", "dct.klaviyodns.com")
        .add("dct.klaviyodns.com", "A", "192.0.2.20")
        .alias("old.mapped.test", "gone.wl.sendgrid.net")
    )


def site(request: httpx.Request) -> httpx.Response:
    if request.url.host == "api.certspotter.com":
        return httpx.Response(200, json=[{"dns_names": ["corp.mapped.test"]}])
    if request.url.host == "crt.sh":
        return httpx.Response(200, json=LOGGED)
    if request.url.host == "mta-sts.mapped.test":
        return httpx.Response(200, text=POLICY)
    body = PAGES.get(str(request.url))
    if body is None:
        return httpx.Response(404)
    return httpx.Response(200, text=body, headers={"content-type": "text/html"})


async def mapped_map():
    async with httpx.AsyncClient(transport=httpx.MockTransport(site)) as http:
        return await map_domain(
            "mapped.test", checked_at=CHECKED, resolver=mapped(), http=http, use_ct=True
        )


async def test_every_claim_and_finding_carries_evidence():
    result = await mapped_map()
    claims = [c for s in result.services for c in s.claims]
    # The fake domain reaches every kind of claim and most kinds of finding.
    assert {c.kind for c in claims} == set(Kind)
    assert len(result.findings) >= 9
    for claim in claims:
        e = claim.evidence
        assert e.name and e.rtype and e.value and e.checked_at == CHECKED, claim
    assert result.historical
    for past in result.historical:
        e = past.evidence
        assert e.name and e.value and e.not_before and e.not_after and e.target, past
    for finding in result.findings:
        assert finding.evidence, f"no evidence: {finding.title}"
        for e in finding.evidence:
            assert e.name and e.rtype and e.value and e.checked_at == CHECKED, finding.title
