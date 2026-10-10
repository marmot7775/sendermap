"""The domain's own website: the signup forms and widgets it loads, and the services its
subprocessor page names.

A script or stylesheet the homepage loads from a service's host is that service running there,
often collecting addresses it will mail later. A service's host appearing anywhere else in the
HTML, in a link, a form or text, is only mentioned. A subprocessor list is the company's own
statement of which services handle its data; a service counts as named when one of its
subprocessor names in vendors.json appears there as a whole word. Each is "Likely" evidence,
never more.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx

from ..model import Checked, Claim, Evidence, Gap, Kind, Observed
from . import Context, http_failure

USER_AGENT = "Sendermap/0.1 (+https://github.com/marmot7775/sendermap)"
MAX_BYTES = 2_000_000
_SUBPROCESSOR_LINK = re.compile(r'href="([^"]*sub-?processors?[^"]*)"', re.IGNORECASE)
_LOADED = re.compile(
    r"<(?:script\b[^>]*?\ssrc|link\b[^>]*?\shref)\s*=\s*[\"']?([^\"'\s>]+)", re.IGNORECASE
)


async def collect(ctx: Context) -> Observed:
    if ctx.http is None:
        return Observed()
    home = f"https://{ctx.domain}/"
    page = await _fetch(ctx.http, home)
    if isinstance(page, str):
        return Observed(gaps=(Gap(f"the website: GET {home}", page),), checked=_page(ctx, home))
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
        tuple(claims), gaps=_cut(f"the website: GET {home}", cut), checked=_page(ctx, home)
    )
    if link := _SUBPROCESSOR_LINK.search(html):
        return observed + await _subprocessors(ctx, urljoin(url, link.group(1)))
    return observed


async def _subprocessors(ctx: Context, url: str) -> Observed:
    assert ctx.http is not None
    page = await _fetch(ctx.http, url)
    if isinstance(page, str):
        gap = Gap(f"the subprocessor page: GET {url}", page)
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
    gaps = _cut(f"the subprocessor page: GET {url}", cut)
    return Observed(tuple(claims), gaps=gaps, checked=_page(ctx, url))


def _page(ctx: Context, url: str) -> tuple[Checked, ...]:
    return (Checked(ctx.domain, pages=(url,)),)


def _cut(asked: str, cut: bool) -> tuple[Gap, ...]:
    happened = f"only the first {MAX_BYTES:,} bytes were read (cap); the rest was not"
    return (Gap(asked, happened),) if cut else ()


async def _fetch(http: httpx.AsyncClient, url: str) -> tuple[str, str, bool] | str:
    """(final URL, HTML, whether the page was cut at MAX_BYTES) for a page that loaded, or what
    happened instead."""
    try:
        async with http.stream(
            "GET", url, headers={"user-agent": USER_AGENT}, follow_redirects=True, timeout=10
        ) as response:
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
    except httpx.HTTPError as e:
        return http_failure(e)
