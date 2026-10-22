"""The terminal view: the View in rich, findings first, then services grouped by tier."""

from __future__ import annotations

from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .view import SenderMap, ServiceView, UnknownView, View, view

_TIER_STYLE = {
    "In use": "bold green",
    "Configured": "bold cyan",
    "Likely": "bold yellow",
    "Account only": "bold bright_black",
}
_SEVERITY_STYLE = {"risk": "bold red", "warning": "yellow", "note": "bright_black"}
_DIM = "bright_black"


def render(result: SenderMap, console: Console, *, evidence: bool = False) -> None:
    """Print the map's View to `console`."""
    show(view(result, evidence=evidence), console)


def show(shown: View, console: Console) -> None:
    """Print one View, each section left out when it is empty."""
    _head(shown, console)
    _findings(shown, console)
    for tier in shown.tiers:
        console.print(Text(f"\n{tier.tier.upper()}", style=_TIER_STYLE[tier.tier]))
        console.print(_services(tier.services))
    if shown.reporting:
        _heading("REPORTS GO TO", console, style="bold magenta")
        console.print(Text(f"  {', '.join(shown.reporting)}"))
    if shown.claimed:
        _heading("CLAIMED SENDERS", console)
        for part in shown.claimed:
            console.print(Text(f"  {part.heading}"))
            for item in part.items:
                console.print(Text(f"    {item}", style=_DIM))
    if shown.unknowns:
        _heading("NOT RECOGNISED", console)
        for unknown in shown.unknowns:
            _unknown(unknown, console)
    _checks(shown, console)


def _checks(shown: View, console: Console) -> None:
    """What the logs, the absences, the gaps and the questions asked say."""
    _dim_section("CERTIFICATE TRANSPARENCY", shown.ct, console)
    if shown.absences:
        _heading("CHECKED AND NOT THERE", console)
        for a in shown.absences:
            console.print(Text(f"  {a.asked}: {a.happened}"))
            for answer in a.answers:
                console.print(Text(f"    {answer}", style=_DIM))
    _dim_section("NOT CHECKED", [f"{g.asked}: {g.happened}" for g in shown.gaps], console)
    if shown.asked:
        _heading("WHAT WAS ASKED", console)
        for record in shown.asked:
            console.print(Text(f"  {record.where}: {record.counts}", style=_DIM))
            for heading, names in record.names:
                console.print(Text(f"    {heading}: {', '.join(names)}", style=_DIM))


def _heading(title: str, console: Console, style: str = "bold") -> None:
    console.print(Text(f"\n{title}", style=style))


def _dim_section(title: str, lines: tuple[str, ...] | list[str], console: Console) -> None:
    if lines:
        _heading(title, console)
        for line in lines:
            console.print(Text(f"  {line}", style=_DIM))


def _head(shown: View, console: Console) -> None:
    """The headline and how the map was made in a panel, then the story under it."""
    head = shown.head
    count = f"{head.senders} sending service{'s' if head.senders != 1 else ''}"
    how = (
        f"{head.lookups} lookups in {head.elapsed:.1f} s over {head.resolver}, "
        f"checked {head.checked_at}"
    )
    headline = Text.assemble((head.domain, "bold"), f"   {count}\n", (how, _DIM))
    console.print(Panel(headline, border_style=_DIM, expand=False))
    if head.story:
        console.print(Text(head.story))


def _findings(shown: View, console: Console) -> None:
    if not shown.findings:
        return
    _heading("NEEDS ATTENTION", console)
    for f in shown.findings:
        console.print(Text.assemble(("  ● ", _SEVERITY_STYLE[f.severity]), (f.title, "bold")))
        console.print(Padding(Text(f.detail, style=_DIM), (0, 0, 0, 4)))
        for record in f.records:
            console.print(Padding(Text(record, style=_DIM), (0, 0, 0, 6)))


def _services(services: tuple[ServiceView, ...]) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(no_wrap=True)
    table.add_column(style=_DIM, no_wrap=True)
    table.add_column(overflow="fold")
    for service in services:
        lines = [Text(f"at {service.where}", style=_DIM)] if service.where else []
        for kind in service.kinds:
            lines.append(Text(str(kind)))
            lines += [Text(f"  {record}", style=_DIM) for record in kind.records]
        if service.setup:
            lines.append(Text(service.setup))
        table.add_row(Text(f"  {service.name}", style="bold"), service.category, Group(*lines))
    return table


def _unknown(item: UnknownView, console: Console) -> None:
    """One unknown with its record, or one network's group: its count line, its ranges and
    addresses, and the records shown, with how many more there are."""
    where = f"  at {item.where}" if item.where else ""
    if item.grouped:
        console.print(Text(f"  {item.label}{where}", style=_DIM))
        console.print(Text(f"    {', '.join(item.values)}", style=_DIM))
    else:
        console.print(Text(f"  {item.label}: {item.values[0]}{where}", style=_DIM))
    for record in item.records:
        console.print(Text(f"    {record}", style=_DIM))
    if item.more:
        console.print(Text(f"    + {item.more} more", style=_DIM))
