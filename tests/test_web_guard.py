"""Every page fetch goes through the guard: https on port 443 only, every address of the host
public, looked up through the map's DNS, and redirects followed by hand with the same checks, at
most five. A refused fetch is a gap and no request is sent."""

import ipaddress
from collections.abc import Callable

import httpx
import pytest
from conftest import PUBLIC, Zone, context

from sendermap.model import Observed
from sendermap.sources import Context, mta_sts, web

HOME = "the website: GET https://example.com/"


async def fetch(
    zone: Zone, handler: Callable[[httpx.Request], httpx.Response]
) -> tuple[Observed, list[str]]:
    """What the web source observed, and every URL it requested."""
    sent: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return handler(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(record)) as http:
        ctx = context(zone)
        observed = await web.collect(
            Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http)
        )
    return observed, sent


def gaps(observed: Observed) -> dict[str, str]:
    return {g.asked: g.happened for g in observed.gaps}


def page(html: str = "<p>hello</p>") -> httpx.Response:
    return httpx.Response(200, text=html, headers={"content-type": "text/html"})


def moved(location: str) -> httpx.Response:
    return httpx.Response(302, headers={"location": location})


@pytest.mark.parametrize(
    ("rtype", "address"),
    [
        ("A", "127.0.0.1"),
        ("A", "169.254.169.254"),
        ("A", "10.0.0.5"),
        ("A", "0.0.0.0"),
        ("A", "224.0.0.1"),
        ("A", "240.0.0.1"),
        ("A", "100.100.100.200"),  # shared address space (RFC 6598), a cloud metadata address
        ("AAAA", "::1"),
        ("AAAA", "fe80::1"),
        ("AAAA", "::ffff:169.254.169.254"),
    ],
)
async def test_a_host_with_a_private_address_is_not_fetched(rtype: str, address: str) -> None:
    zone = Zone().public("example.com").add("example.com", rtype, address)
    observed, sent = await fetch(zone, lambda request: page())
    assert sent == []
    shown = ipaddress.ip_address(address)
    assert gaps(observed) == {HOME: f"not fetched: resolves to a private address ({shown})"}


async def test_a_failed_address_lookup_is_not_fetched() -> None:
    observed, sent = await fetch(Zone(failing={"example.com"}), lambda request: page())
    assert sent == []
    assert gaps(observed) == {HOME: "not fetched: address lookup failed"}


async def test_a_host_with_no_address_is_not_fetched() -> None:
    observed, sent = await fetch(Zone(), lambda request: page())
    assert sent == []
    assert gaps(observed) == {HOME: "not fetched: no address"}


async def test_the_addresses_are_asked_through_the_maps_dns() -> None:
    zone = Zone().public("example.com")
    await fetch(zone, lambda request: page())
    assert {("example.com", "A"), ("example.com", "AAAA")} <= set(zone.asked)


@pytest.mark.parametrize(
    ("location", "reason"),
    [
        ("http://example.com/", "http is not https"),
        ("https://example.com:8443/", "port 8443 is not 443"),
        ("https://169.254.169.254/latest/meta-data/", "resolves to a private address"),
        ("https://inside.example.net/", "resolves to a private address (10.1.2.3)"),
        ("https://gone.example.net/", "no address"),
        ("https://junk.example.net/", "address lookup failed"),
    ],
)
async def test_every_redirect_is_checked_before_it_is_followed(location: str, reason: str) -> None:
    zone = (
        Zone()
        .public("example.com")
        .add("inside.example.net", "A", "10.1.2.3")
        .add("junk.example.net", "A", "not an address")
    )
    observed, sent = await fetch(zone, lambda request: moved(location))
    assert sent == ["https://example.com/"]
    assert gaps(observed)[HOME].startswith(f"not fetched: {reason}")


async def test_five_redirects_are_followed_and_a_sixth_is_a_gap() -> None:
    def hops(limit: int) -> Callable[[httpx.Request], httpx.Response]:
        def handler(request: httpx.Request) -> httpx.Response:
            step = int(request.url.params.get("n", "0"))
            return moved(f"/?n={step + 1}") if step < limit else page()

        return handler

    zone = Zone().public("example.com")
    observed, sent = await fetch(zone, hops(5))
    assert len(sent) == 6 and gaps(observed) == {}
    observed, sent = await fetch(zone, hops(6))
    assert len(sent) == 6
    assert gaps(observed) == {HOME: "not fetched: more than 5 redirects"}


async def test_a_redirect_to_a_public_host_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return moved("https://www.example.com/")
        return page('<script src="https://static.klaviyo.com/onsite/js/x.js"></script>')

    zone = Zone().public("example.com", "www.example.com")
    observed, sent = await fetch(zone, handler)
    assert sent == ["https://example.com/", "https://www.example.com/"]
    (claim,) = observed.claims
    assert claim.evidence.name == "https://www.example.com/"


@pytest.mark.parametrize(
    ("url", "reason"),
    [("https://example.com:https/", "the port is not a number"), ("https:///no-host", "no host")],
)
async def test_a_url_the_guard_cannot_read_is_refused(url: str, reason: str) -> None:
    assert await web.refusal(context(Zone()).dns, url) == reason


async def test_a_redirect_to_a_public_address_is_followed_without_a_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return moved(f"https://{PUBLIC}/") if request.url.host == "example.com" else page()

    zone = Zone().public("example.com")
    observed, sent = await fetch(zone, handler)
    assert sent == ["https://example.com/", f"https://{PUBLIC}/"]
    assert gaps(observed) == {}
    assert (PUBLIC, "A") not in zone.asked


@pytest.mark.parametrize(
    ("answer", "happened"),
    [
        (
            httpx.Response(200, text="{}", headers={"content-type": "application/json"}),
            "not a web page (application/json)",
        ),
        (httpx.Response(200, content=b"<p>hi</p>"), "not a web page (no content type)"),
        (httpx.Response(503), "HTTP 503"),
    ],
)
async def test_an_answer_that_is_not_a_page_is_a_gap(answer: httpx.Response, happened: str) -> None:
    observed, _ = await fetch(Zone().public("example.com"), lambda request: answer)
    assert gaps(observed) == {HOME: happened}


async def test_a_request_that_fails_is_a_gap_naming_the_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    observed, _ = await fetch(Zone().public("example.com"), handler)
    assert gaps(observed) == {HOME: "failed: ConnectError"}


async def test_without_a_web_client_the_website_is_not_read() -> None:
    ctx = context(Zone().public("example.com"))
    assert await web.collect(ctx) == Observed()


async def test_the_subprocessor_link_goes_through_the_guard() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return page('<a href="https://legal.example.net/subprocessors">Subprocessors</a>')

    zone = Zone().public("example.com").add("legal.example.net", "A", "127.0.0.1")
    observed, sent = await fetch(zone, handler)
    assert sent == ["https://example.com/"]
    assert gaps(observed) == {
        "the subprocessor page: GET https://legal.example.net/subprocessors": (
            "not fetched: resolves to a private address (127.0.0.1)"
        )
    }


async def test_a_subprocessor_page_on_another_public_host_is_read() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return page('<a href="https://legal.example.net/subprocessors">Subprocessors</a>')
        return page("<td>Zendesk</td>")

    zone = Zone().public("example.com", "legal.example.net")
    observed, _ = await fetch(zone, handler)
    assert {c.service for c in observed.claims} == {"Zendesk"}


async def test_an_mta_sts_policy_host_with_a_private_address_is_not_fetched() -> None:
    zone = (
        Zone()
        .add("_mta-sts.example.com", "TXT", "v=STSv1; id=1")
        .add("mta-sts.example.com", "A", "169.254.169.254")
    )
    sent: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(200, text="version: STSv1\nmode: testing\n")

    async with httpx.AsyncClient(transport=httpx.MockTransport(record)) as http:
        ctx = context(zone)
        observed = await mta_sts.collect(
            Context(ctx.domain, ctx.dns, ctx.catalog, ctx.checked_at, http)
        )
    assert sent == []
    assert gaps(observed) == {
        "MTA-STS policy: GET https://mta-sts.example.com/.well-known/mta-sts.txt": (
            "not fetched: resolves to a private address (169.254.169.254)"
        )
    }
