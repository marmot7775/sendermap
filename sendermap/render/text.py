"""The terminal view: services grouped by tier, each with the evidence that decided it."""

from __future__ import annotations

from datetime import UTC
from itertools import groupby

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..model import SenderMap, Service, Severity, Tier

_TIER_STYLE = {
    Tier.IN_USE: "bold green",
    Tier.CONFIGURED: "bold cyan",
    Tier.LIKELY: "bold yellow",
    Tier.ACCOUNT_ONLY: "bold bright_black",
}
_SEVERITY_STYLE = {
    Severity.RISK: "bold red",
    Severity.WARNING: "yellow",
    Severity.NOTE: "bright_black",
}


def render(result: SenderMap, console: Console, *, evidence: bool = False) -> None:
    senders = result.senders
    headline = Text.assemble(
        (result.domain, "bold"),
        f"   {len(senders)} sending service{'s' if len(senders) != 1 else ''}",
        (f"   {result.run.lookups} lookups in {result.run.elapsed:.1f} s", "bright_black"),
    )
    console.print(Panel(headline, border_style="bright_black", expand=False))
    for tier, group in groupby(senders, key=lambda s: s.tier):
        console.print(Text(f"\n{tier.value.upper()}", style=_TIER_STYLE[tier]))
        console.print(_services(list(group), result.domain, evidence))
    if result.reporting:
        console.print(Text("\nREPORTS GO TO", style="bold magenta"))
        console.print(_services(list(result.reporting), result.domain, evidence))
    if result.findings:
        console.print(Text("\nNEEDS ATTENTION", style="bold"))
        for f in result.findings:
            console.print(Text.assemble(("  ● ", _SEVERITY_STYLE[f.severity]), (f.title, "bold")))
            console.print(Text(f"    {f.detail}", style="bright_black"))
    if result.unknowns:
        console.print(Text("\nNOT RECOGNISED", style="bold"))
        for u in result.unknowns:
            where = "" if u.where == result.domain else f"  at {u.where}"
            console.print(Text(f"  {u.what}: {u.value}{where}", style="bright_black"))
    checked = result.run.checked_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    footer = [f"Checked {result.domain} on {checked}"]
    if result.subdomains_checked:
        footer.append(f"and {len(result.subdomains_checked)} sending subdomains")
    for gap in result.gaps:
        footer.append(f"\nNot checked: {gap.asked} ({gap.happened})")
    console.print(Text("\n" + " ".join(footer), style="bright_black"))


def _services(services: list[Service], domain: str, evidence: bool) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(no_wrap=True)
    table.add_column(style="bright_black", no_wrap=True)
    table.add_column(overflow="fold")
    for service in services:
        claims = service.claims if evidence else (service.decided_by,)
        lines = [_claim_line(c.kind.value, str(c.evidence), c.where, domain) for c in claims]
        if not evidence and len(service.claims) > 1:
            lines.append(Text(f"+ {len(service.claims) - 1} more", style="bright_black"))
        table.add_row(Text(f"  {service.name}", style="bold"), service.category, Group(*lines))
    return table


def _claim_line(kind: str, evidence: str, where: str, domain: str) -> Text:
    at = "" if where == domain else f" at {where}"
    return Text.assemble((kind + at, ""), ("\n" + evidence, "bright_black"))
