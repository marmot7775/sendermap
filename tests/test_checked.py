"""Rule 3: the map says what was asked at each name, and every view shows it with the gaps."""

import httpx
from conftest import CHECKED, Zone
from rich.console import Console

from sendermap import catalog, engine, map_domain
from sendermap.model import SenderMap
from sendermap.render import markdown, text


def acme() -> Zone:
    return (
        Zone(failing={"_dmarc.acme.test"})
        .public("acme.test")
        .add("acme.test", "TXT", "v=spf1 include:_spf.google.com ~all")
        .add("email.acme.test", "TXT", "v=spf1 include:mailgun.org ~all")
        .selectors_exist("acme.test")
        .selectors_exist("email.acme.test")
    )


async def acme_map() -> SenderMap:
    def site(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.certspotter.com":
            return httpx.Response(200, json=[])
        if request.url.host == "acme.test":
            html = '<a href="/subprocessors">Subprocessors</a>'
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(site)) as http:
        return await map_domain("acme.test", checked_at=CHECKED, resolver=acme(), http=http)


async def test_each_name_records_the_dkim_names_labels_and_pages_asked() -> None:
    result = await acme_map()
    apex, sub = result.checked
    assert apex.where == "acme.test" and sub.where == "email.acme.test"
    assert apex.pages == (
        "https://acme.test/",
        "https://acme.test/subprocessors",
        "https://api.certspotter.com/v1/issuances?domain=acme.test&include_subdomains=true"
        "&expand=dns_names",
    )
    assert "bounce" in apex.labels and "links" in apex.labels
    sweep = catalog.load().probe_selectors
    assert "google" in apex.dkim_selectors and set(apex.dkim_selectors) == set(sweep)
    assert len(sub.dkim_selectors) >= engine.SUBDOMAIN_PROBES and sub.labels == ()


async def test_the_checked_record_holds_every_dkim_name_the_scan_asked() -> None:
    zone = acme()
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, use_web=False, use_subdomains=False
    )
    asked = {
        name.removesuffix("._domainkey.acme.test")
        for name, rtype in zone.asked
        if rtype == "TXT" and name.endswith("._domainkey.acme.test")
    }
    (apex,) = result.checked
    assert asked - {"sendermap-wildcard-check"} == set(apex.dkim_selectors)


async def test_markdown_shows_the_gaps_and_what_was_asked() -> None:
    page = markdown.render(await acme_map())
    assert "## Not checked" in page
    assert "- DMARC: TXT at _dmarc.acme.test: lookup failed" in page
    assert "## What was asked" in page
    assert "- **email.acme.test**:" in page and "`google`" in page


async def test_the_terminal_shows_the_gaps_and_what_was_asked() -> None:
    console = Console(record=True, width=200)
    text.render(await acme_map(), console)
    shown = console.export_text()
    assert "Not checked: DMARC: TXT at _dmarc.acme.test (lookup failed)" in shown
    assert "Asked at acme.test:" in shown and "Asked at email.acme.test:" in shown
    console = Console(record=True, width=400)
    text.render(await acme_map(), console, evidence=True)
    assert "DKIM selectors: " in console.export_text()


async def test_the_json_carries_the_checked_record() -> None:
    data = (await acme_map()).to_dict()
    assert data["checked"][0]["where"] == "acme.test"
    assert {"dkim_selectors", "labels", "pages"} <= set(data["checked"][0])
