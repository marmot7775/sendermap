"""The terminal view: services grouped by tier, each with the evidence that decided it."""

from __future__ import annotations

from datetime import UTC
from itertools import groupby

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..model import Claim, SenderMap, Service, Severity, Tier, Unknown
from ..setup import line
from . import (
    NetworkGroup,
    asked,
    asked_in_full,
    claimed_parts,
    ct_lines,
    grouped_unknowns,
    resolver_words,
)

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
    _head(result, console)
    for tier, group in groupby(senders, key=lambda s: s.tier):
        console.print(Text(f"\n{tier.value.upper()}", style=_TIER_STYLE[tier]))
        console.print(_services(list(group), result.domain, evidence))
    if result.reporting:
        console.print(Text("\nREPORTS GO TO", style="bold magenta"))
        console.print(_services(list(result.reporting), result.domain, evidence))
    _claimed(result, console)
    if result.findings:
        console.print(Text("\nNEEDS ATTENTION", style="bold"))
        for f in result.findings:
            console.print(Text.assemble(("  ● ", _SEVERITY_STYLE[f.severity]), (f.title, "bold")))
            console.print(Text(f"    {f.detail}", style="bright_black"))
    if result.unknowns:
        console.print(Text("\nNOT RECOGNISED", style="bold"))
        for item in grouped_unknowns(result.unknowns):
            _unknown(item, result.domain, console, evidence)
    if lines := ct_lines(result):
        console.print(Text("\nCERTIFICATE TRANSPARENCY", style="bold"))
        for line in lines:
            console.print(Text(f"  {line}", style="bright_black"))
    _absences(result, console)
    checked = result.run.checked_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    footer = [f"Checked {result.domain} on {checked}"]
    if result.subdomains_checked:
        footer.append(f"and {len(result.subdomains_checked)} sending subdomains")
    for gap in result.gaps:
        footer.append(f"\nNot checked: {gap.asked} ({gap.happened})")
    for record in result.checked:
        footer.append(f"\nAsked at {record.where}: {asked(record)}")
        if evidence:
            footer += [
                f"\n  {heading}: {', '.join(names)}" for heading, names in asked_in_full(record)
            ]
    console.print(Text("\n" + " ".join(footer), style="bright_black"))


def _unknown(item: Unknown | NetworkGroup, domain: str, console: Console, evidence: bool) -> None:
    """One unknown with its record, or one network's group: its count line, its ranges and
    addresses, and the first record, or every record with --evidence."""
    where = "" if item.where == domain else f"  at {item.where}"
    if isinstance(item, Unknown):
        console.print(Text(f"  {item.what}: {item.value}{where}", style="bright_black"))
        console.print(Text(f"    {item.evidence}", style="bright_black"))
        return
    console.print(Text(f"  {item.heading()}{where}", style="bright_black"))
    console.print(Text(f"    {', '.join(cidr for cidr, _ in item.members)}", style="bright_black"))
    shown = item.members if evidence else item.members[:1]
    for _, u in shown:
        console.print(Text(f"    {u.evidence}", style="bright_black"))
    if len(shown) < len(item.members):
        console.print(Text(f"    + {len(item.members) - len(shown)} more", style="bright_black"))


def _head(result: SenderMap, console: Console) -> None:
    """The headline, then the story under it."""
    count = len(result.senders)
    headline = Text.assemble(
        (result.domain, "bold"),
        f"   {count} sending service{'s' if count != 1 else ''}",
        (
            f"   {result.run.lookups} lookups in {result.run.elapsed:.1f} s "
            f"over {resolver_words(result.run.resolver)}",
            "bright_black",
        ),
    )
    console.print(Panel(headline, border_style="bright_black", expand=False))
    if result.story:
        console.print(Text(result.story))


def _claimed(result: SenderMap, console: Console) -> None:
    """The services the client claimed against the map, in four parts, when any were claimed."""
    if not result.reconciliation:
        return
    console.print(Text("\nCLAIMED SENDERS", style="bold"))
    for heading, lines in claimed_parts(result.reconciliation):
        console.print(Text(f"  {heading}"))
        for item in lines:
            console.print(Text(f"    {item}", style="bright_black"))


def _absences(result: SenderMap, console: Console) -> None:
    """What was asked and shown not to be there, each with the negative answers that show it."""
    if not result.absences:
        return
    console.print(Text("\nCHECKED AND NOT THERE", style="bold"))
    for a in result.absences:
        console.print(Text(f"  {a.asked}: {a.happened}"))
        for e in a.evidence:
            console.print(Text(f"    {e}", style="bright_black"))


def _services(services: list[Service], domain: str, evidence: bool) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(no_wrap=True)
    table.add_column(style="bright_black", no_wrap=True)
    table.add_column(overflow="fold")
    for service in services:
        claims = service.claims if evidence else (service.decided_by,)
        lines = [_claim_line(c, domain) for c in claims]
        if not evidence and len(service.claims) > 1:
            lines.append(Text(f"+ {len(service.claims) - 1} more", style="bright_black"))
        lines += [Text(line(setup)) for setup in service.setups]
        table.add_row(Text(f"  {service.name}", style="bold"), service.category, Group(*lines))
    return table


def _claim_line(claim: Claim, domain: str) -> Text:
    """The kind of claim, its record, and any record supporting it, one per line."""
    at = "" if claim.where == domain else f" at {claim.where}"
    records = [str(claim.evidence), *(f"via {e}" for e in claim.supporting)]
    return Text.assemble((claim.kind.value + at, ""), ("\n" + "\n".join(records), "bright_black"))
