"""BIMI: the brand logo a domain publishes for inboxes to show. Shown on the map, not evidence
of any service."""

from __future__ import annotations

from . import Context


async def logo(ctx: Context) -> str | None:
    answer = await ctx.dns.txt(f"default._bimi.{ctx.domain}")
    for record in answer.records:
        tags = dict(p.strip().partition("=")[::2] for p in record.split(";"))
        url = tags.get("l", "").strip()
        if tags.get("v", "").strip().upper() == "BIMI1" and url.startswith("https://"):
            return url
    return None
