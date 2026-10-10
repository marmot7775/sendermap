"""The domain's own website: the signup forms and widgets it loads, and the services its
subprocessor page names.

A script on the homepage is the service running there, usually collecting addresses it will
mail later; it is "Likely" evidence, never more. A subprocessor list is the company's own
statement of which services handle its data.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from ..model import Claim, Evidence, Gap, Kind, Observed
from . import Context

USER_AGENT = "Sendermap/0.1 (+https://github.com/marmot7775/sendermap)"
MAX_BYTES = 2_000_000
_SENDING_CATEGORIES = frozenset(
    {
        "Mailbox",
        "Marketing",
        "Transactional",
        "Support and CRM",
        "Security gateway",
        "Commerce and apps",
    }
)
_SUBPROCESSOR_LINK = re.compile(r'href="([^"]*sub-?processors?[^"]*)"', re.IGNORECASE)


async def collect(ctx: Context) -> Observed:
    if ctx.http is None:
        return Observed()
    home = f"https://{ctx.domain}/"
    page = await _fetch(ctx.http, home)
    if page is None:
        return Observed(gaps=(Gap(f"the website at {home}", "it did not load"),))
    url, html = page
    claims = [
        Claim(
            service,
            Kind.WEBSITE,
            ctx.domain,
            Evidence(url, "page", f"loads {host}", ctx.checked_at),
        )
        for service, host in ctx.catalog.website_services(html).items()
    ]
    if link := _SUBPROCESSOR_LINK.search(html):
        claims += await _subprocessors(ctx, urljoin(url, link.group(1)))
    return Observed(tuple(claims))


async def _subprocessors(ctx: Context, url: str) -> list[Claim]:
    assert ctx.http is not None
    page = await _fetch(ctx.http, url)
    if page is None:
        return []
    text = re.sub(r"<[^>]+>", " ", page[1])
    return [
        Claim(
            service,
            Kind.WEBSITE,
            ctx.domain,
            Evidence(page[0], "page", f"names {service}", ctx.checked_at),
        )
        for service in ctx.catalog
        if ctx.catalog.category(service) in _SENDING_CATEGORIES
        and len(service) >= 5  # short names ("Kit", "Wix") are ordinary words too
        and re.search(rf"\b{re.escape(service)}\b", text)
    ]


async def _fetch(http: httpx.AsyncClient, url: str) -> tuple[str, str] | None:
    try:
        async with http.stream(
            "GET", url, headers={"user-agent": USER_AGENT}, follow_redirects=True, timeout=10
        ) as response:
            if response.status_code != 200 or "html" not in response.headers.get(
                "content-type", ""
            ):
                return None
            body = b""
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > MAX_BYTES:
                    break
            return str(response.url), body.decode(response.encoding or "utf-8", errors="replace")
    except httpx.HTTPError:
        return None
