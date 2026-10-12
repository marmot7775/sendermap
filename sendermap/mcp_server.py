"""Sendermap as an MCP server: `sendermap mcp` serves it over stdio, and the website mounts the
same server at /mcp. It needs the `mcp` extra.

Two tools, both read only: `sendermap_map` maps a domain and returns the sendermap/1 JSON as
structured content, validated against the schema it declares as its output schema;
`sendermap_vendor` returns one vendor's block from the vendor data. Two resources: the schema
and the vendor list. The tools build nothing of their own: the map is `map_domain`'s, the story
is the map's, the claimed sections are `render.claimed_parts`'s.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from importlib import resources
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import ToolResult
from jsonschema import Draft202012Validator
from mcp.types import TextContent, ToolAnnotations
from pydantic import Field

from . import __version__, catalog, schema
from .cli import unreadable
from .engine import Progress, clean_domain, map_domain
from .model import SenderMap
from .reconcile import names, with_claimed
from .render import claimed_parts
from .sources.ct import default_cache

SCHEMA_URI = "sendermap://schema/sendermap-1.json"
VENDORS_URI = "sendermap://vendors"

INSTRUCTIONS = """\
Sendermap maps the services that send email as a domain from public records only: DNS, \
certificate logs and the domain's own website. Each sending service has a tier, the strongest \
its claims support:
- In use: the service's MX at the domain itself.
- Configured: a record that sets the service up to send as the domain, such as an SPF include, \
a DKIM key served through a CNAME into its zone, a bounce or tracking CNAME, or a subdomain \
delegated to it.
- Likely: a guess from a name, such as a DKIM key known only by its selector name, a script on \
the homepage or a subprocessor list. A Likely service is never Configured.
- Account only: a trace of an account, such as a verification token or a revoked key, not a \
sign that it sends.
A service whose role is reporting only receives DMARC or TLS reports and has no tier.
Read absences and gaps as written. An absence is a question answered "not there". A gap is a \
question that got no usable answer, or a check that was capped or turned off, and is not an \
absence. Silence is not absence: a service missing from the map may sit behind a gap, a hosted \
SPF record or a selector nobody knows. Quote the record behind any claim you repeat, and say \
what was not checked.
Each setup holds what the domain publishes against what the vendor's documentation asks for.
A result states what public records showed when they were checked. A finding may name the \
documented standard remedy for what it found; that is a statement about the standard, not advice \
about this domain. A result does not show sending volume or reputation, or that a published DKIM \
key signs anything."""

MAP_DESCRIPTION = (
    "Maps the services that send email as a domain from public records (DNS, certificate logs "
    "and the domain's homepage), each with a tier, the record that shows it and the vendor's "
    "documented setup. Use it to find who sends mail as a domain, or, with claimed, to hold the "
    "services the domain's owner says they use against what the records show. domain is the "
    "domain to map; claimed is the service names the owner gave; website reads the homepage and "
    "subprocessor page; subdomains searches for sending subdomains (email, mg and the like); "
    "certificate_log also reads crt.sh and resolves every logged name, which is slow; detail is "
    "summary (each service's deciding claim and setups) or full (every claim, and what was asked "
    "at each name). It does not return sending volume, reputation or proof that a DKIM key is in "
    "use, and a service it does not show may sit behind one of the gaps it lists."
)

VENDOR_DESCRIPTION = (
    "Returns one vendor's block from Sendermap's vendor data as JSON: its category, aliases, "
    "every pattern Sendermap recognises it by (SPF includes, MX hosts, DKIM selectors and "
    "CNAMEs, bounce and tracking hosts, tokens, networks and the rest), each with the live "
    "record that proves it, its documented setup and its sending address. Use it to see why a "
    "map credited a service, or which records a vendor's setup asks for. name is the vendor's "
    "name or one of its aliases, matched exactly once case, spaces and punctuation are dropped. "
    "It looks nothing up for any domain and says nothing about sending volume or who uses the "
    "vendor."
)


@dataclass(frozen=True, slots=True)
class Options:
    """The checks a caller may turn on or off, as map_domain takes them."""

    use_web: bool = True
    use_subdomains: bool = True
    use_ct: bool = False


# Builds the map for a cleaned domain. The website's build adds its rate limits and cache.
Build = Callable[[str, Options, Progress], Awaitable[SenderMap]]


async def local(domain: str, options: Options, progress: Progress) -> SenderMap:
    """The build `sendermap mcp` uses: this machine's resolver, certificate logs cached on disk."""
    return await map_domain(
        domain,
        checked_at=datetime.now(UTC),
        use_web=options.use_web,
        use_subdomains=options.use_subdomains,
        use_ct=options.use_ct,
        ct_cache=default_cache(),
        progress=progress,
    )


def create(build: Build = local) -> FastMCP:
    """The server, with its tools and resources, mapping through `build`."""
    server = FastMCP("Sendermap", instructions=INSTRUCTIONS, version=__version__)

    @server.tool(
        name="sendermap_map",
        title="Map a domain's email senders",
        description=MAP_DESCRIPTION,
        output_schema=schema(),
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=True),
    )
    async def sendermap_map(
        domain: Annotated[str, Field(description="The domain to map, such as example.com.")],
        *,
        ctx: Context,
        claimed: Annotated[
            list[str], Field(description="Service names the domain's owner says they use.")
        ] = [],  # noqa: B006 (pydantic copies the default)
        website: Annotated[
            bool, Field(description="Read the homepage and subprocessor page.")
        ] = True,
        subdomains: Annotated[
            bool, Field(description="Search for sending subdomains, such as email and mg.")
        ] = True,
        certificate_log: Annotated[
            bool, Field(description="Also read crt.sh and resolve every logged name. Slow.")
        ] = False,
        detail: Annotated[
            Literal["summary", "full"],
            Field(description="summary: each service's deciding claim. full: everything."),
        ] = "summary",
    ) -> ToolResult:
        try:
            cleaned = clean_domain(domain)
        except ValueError as e:
            raise ToolError(f"{domain!r} does not look like a domain.") from e
        steps = 0

        async def progress(step: str) -> None:
            nonlocal steps
            steps += 1
            await ctx.report_progress(steps, message=step)

        options = Options(use_web=website, use_subdomains=subdomains, use_ct=certificate_log)
        built = await build(cleaned, options, progress)
        if why := unreadable(built):
            raise ToolError(f"No map: {cleaned}'s own records could not be read ({why}).")
        result = with_claimed(built, names(claimed), catalog.load())
        data = structured(result, detail)
        if errors := sorted(e.message for e in _validator().iter_errors(data)):
            raise ToolError(f"The map broke the sendermap/1 schema: {errors[0]}")
        story = TextContent(type="text", text=text(result))
        return ToolResult(content=[story], structured_content=data)

    @server.tool(
        name="sendermap_vendor",
        title="Show a vendor's patterns and setup",
        description=VENDOR_DESCRIPTION,
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
    )
    def sendermap_vendor(
        name: Annotated[str, Field(description="A vendor's name or alias, such as Office 365.")],
    ) -> ToolResult:
        vendor = catalog.load().named(name)
        if vendor is None:
            raise ToolError(f"No vendor goes by {name!r}. The vendor list is at {VENDORS_URI}.")
        raw = _vendors()["vendors"][vendor]
        block = {"name": vendor, "category": raw["category"], "aliases": raw.get("aliases", [])}
        block |= {k: v for k, v in raw.items() if k not in block}
        listed = TextContent(type="text", text=json.dumps(block, indent=2))
        return ToolResult(content=[listed], structured_content=block)

    @server.resource(
        SCHEMA_URI,
        name="sendermap-1-schema",
        title="The sendermap/1 JSON Schema",
        description="The JSON Schema every map keeps. It grows by addition only.",
        mime_type="application/schema+json",
    )
    def schema_resource() -> str:
        return json.dumps(schema(), indent=2)

    @server.resource(
        VENDORS_URI,
        name="vendors",
        title="The vendors Sendermap knows",
        description="Every vendor in the vendor data, with its category and aliases.",
        mime_type="application/json",
    )
    def vendors_resource() -> str:
        vendors = _vendors()["vendors"]
        rows = [
            {"name": n, "category": b["category"], "aliases": b.get("aliases", [])}
            for n, b in vendors.items()
        ]
        return json.dumps(rows, indent=2)

    return server


def structured(result: SenderMap, detail: str) -> dict[str, Any]:
    """The sendermap/1 JSON. full is to_dict() as it is. summary keeps the same shape with each
    service's deciding claim alone beside its setups, and leaves out what was asked at each name
    (`checked` and `subdomains_checked`), so a busy domain's map stays small and still valid."""
    data: dict[str, Any] = json.loads(json.dumps(result.to_dict(), default=str))
    if detail == "full":
        return data
    for service, row in zip(result.services, data["services"], strict=True):
        row["claims"] = [row["claims"][service.claims.index(service.decided_by)]]
    data.pop("checked", None)
    data.pop("subdomains_checked", None)
    return data


def text(result: SenderMap) -> str:
    """The story, then each finding on one line, then the claimed sections when a list was
    given: the words the Markdown view uses."""
    lines = [result.story or f"Sendermap: {result.domain}"]
    if result.findings:
        lines += ["", "Needs attention:"]
        lines += [f"- {f.title} ({f.severity.value}). {f.detail}" for f in result.findings]
    if result.reconciliation:
        lines += ["", "Claimed senders:"]
        for heading, items in claimed_parts(result.reconciliation):
            lines.append(f"{heading}: {'; '.join(items)}")
    return "\n".join(lines)


@cache
def _validator() -> Draft202012Validator:
    return Draft202012Validator(schema())


@cache
def _vendors() -> dict[str, Any]:
    raw: dict[str, Any] = json.loads(
        resources.files("sendermap").joinpath("data/vendors.json").read_text()
    )
    return raw


def serve() -> None:
    """`sendermap mcp`: the server over stdio."""
    create().run(transport="stdio", show_banner=False)
