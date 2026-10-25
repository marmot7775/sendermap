"""The domain's own website: the signup forms and widgets it loads, and the services its
subprocessor page names.

A script or stylesheet the homepage loads from a service's host is that service running there,
often collecting addresses it will mail later. A service's host appearing anywhere else in the
HTML, in a link, a form or text, is only mentioned. A subprocessor list is the company's own
statement of which services handle its data; a service counts as named when one of its
subprocessor names in vendors.json appears there as a whole word. Each is "Likely" evidence,
never more.

Every page is fetched through a guard, since the address a domain points its pages at is the
domain's choice: https on port 443 only, every address of the host public, and redirects followed
by hand, at most MAX_REDIRECTS, each Location checked the same way. The address is checked before
the request and not pinned during it, so a name that changes its answer between the check and the
connection is not caught.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from urllib.parse import urljoin, urlsplit

import httpx

from ..dns import Lookups, Status
from ..model import Checked, Claim, Evidence, Gap, GapKind, Kind, Observed
from . import Context, http_failure

USER_AGENT = "Sendermap/0.1 (+https://github.com/marmot7775/sendermap)"
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5
# RFC 6598 shared address space: carrier NAT, and some clouds' metadata services. Python
# counts it neither private nor global, so it is named here.
_SHARED = ipaddress.ip_network("100.64.0.0/10")
_SUBPROCESSOR_LINK = re.compile(r'href="([^"]*sub-?processors?[^"]*)"', re.IGNORECASE)
_LOADED = re.compile(
    r"<(?:script\b[^>]*?\ssrc|link\b[^>]*?\shref)\s*=\s*[\"']?([^\"'\s>]+)", re.IGNORECASE
)


async def collect(ctx: Context) -> Observed:
    if ctx.http is None:
        return Observed()
    home = f"https://{ctx.domain}/"
    page = await _fetch(ctx, home)
    if isinstance(page, str):
        gap = Gap(f"the website: GET {home}", page, GapKind.WEBSITE)
        return Observed(gaps=(gap,), checked=_page(ctx, home))
    url, html, cut = page
    loaded = (urlsplit(urljoin(url, src)).hostname or "" for src in _LOADED.findall(html))
    claims = [
        Claim(
            service,
            Kind.WEBSITE if loads else Kind.WEBSITE_MENTION,
            ctx.domain,
            Evidence(url, "page", f"loads {host}" if loads else f"mentions {host}", ctx.checked_at),
        )
        for service, (host, loads) in ctx.catalog.website_services(html, loaded).items()
    ]
    observed = Observed(
        tuple(claims),
        gaps=_cut(f"the website: GET {home}", cut, GapKind.WEBSITE),
        checked=_page(ctx, home),
    )
    if link := _SUBPROCESSOR_LINK.search(html):
        return observed + await _subprocessors(ctx, urljoin(url, link.group(1)))
    return observed


async def _subprocessors(ctx: Context, url: str) -> Observed:
    assert ctx.http is not None
    page = await _fetch(ctx, url)
    if isinstance(page, str):
        gap = Gap(f"the subprocessor page: GET {url}", page, GapKind.PAGE)
        return Observed(gaps=(gap,), checked=_page(ctx, url))
    final, html, cut = page
    text = re.sub(r"<[^>]+>", " ", html)
    found = {
        service: name
        for name, service in ctx.catalog.subprocessor_names.items()
        if re.search(rf"\b{re.escape(name)}\b", text)
    }
    claims = (
        Claim(
            service,
            Kind.SUBPROCESSOR,
            ctx.domain,
            Evidence(final, "page", f"names {name}", ctx.checked_at),
        )
        for service, name in found.items()
    )
    gaps = _cut(f"the subprocessor page: GET {url}", cut, GapKind.PAGE)
    return Observed(tuple(claims), gaps=gaps, checked=_page(ctx, url))


def _page(ctx: Context, url: str) -> tuple[Checked, ...]:
    return (Checked(ctx.domain, pages=(url,)),)


def _cut(asked: str, cut: bool, kind: GapKind) -> tuple[Gap, ...]:
    happened = (
        f"the rest was not read. The first {MAX_BYTES:,} bytes were read (cap {MAX_BYTES:,} bytes)."
    )
    return (Gap(asked, happened, kind, cap=MAX_BYTES),) if cut else ()


async def _fetch(ctx: Context, url: str) -> tuple[str, str, bool] | str:
    """(final URL, HTML, whether the page was cut at MAX_BYTES) for a page that loaded, or what
    happened instead."""
    assert ctx.http is not None
    try:
        for _ in range(MAX_REDIRECTS + 1):
            if refused := await refusal(ctx.dns, url):
                return f"not fetched: {refused}"
            async with ctx.http.stream(
                "GET", url, headers={"user-agent": USER_AGENT}, follow_redirects=False, timeout=10
            ) as response:
                if response.is_redirect:
                    url = urljoin(url, response.headers["location"])
                    continue
                if response.status_code != 200:
                    return f"HTTP {response.status_code}"
                kind = response.headers.get("content-type", "")
                if "html" not in kind:
                    return f"not a web page ({kind or 'no content type'})"
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BYTES:
                        break
                html = body[:MAX_BYTES].decode(response.encoding or "utf-8", errors="replace")
                return str(response.url), html, len(body) > MAX_BYTES
        return f"not fetched: more than {MAX_REDIRECTS} redirects"
    except httpx.HTTPError as e:
        return http_failure(e)


async def refusal(dns: Lookups, url: str) -> str | None:
    """Why a URL may not be fetched, or None when it may: it must be https on port 443, and
    every address its host resolves to must be public."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        return f"{parts.scheme or 'no scheme'} is not https"
    try:
        port = parts.port
    except ValueError:
        return "the port is not a number"
    if port not in (None, 443):
        return f"port {port} is not 443"
    addresses = await _addresses(dns, parts.hostname or "")
    if isinstance(addresses, str):
        return addresses
    private = [a for a in addresses if _private(a)]
    return f"resolves to a private address ({private[0]})" if private else None


async def _addresses(
    dns: Lookups, host: str
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address] | str:
    """Every address of the host (the host itself when it is one), or why there are none."""
    if not host:
        return "no host"
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    answers = await asyncio.gather(dns.query(host, "A"), dns.query(host, "AAAA"))
    try:
        found = [ipaddress.ip_address(r) for a in answers if a.ok for r in a.records]
    except ValueError:
        return "address lookup failed"
    if any(a.status is Status.FAILED for a in answers):
        return "address lookup failed"
    return found or "no address"


def _private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address in _SHARED
    )
