"""The terminal view: the View in rich, findings first, then services grouped by tier."""

from __future__ import annotations

from rich.console import Console
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
        _services(tier.services, console)
    if shown.reporting:
        _heading("REPORTS GO TO", console, style="bold magenta")
        _line(", ".join(shown.reporting), console, 2)
    if shown.claimed:
        _heading("CLAIMED SENDERS", console)
        for part in shown.claimed:
            _line(part.heading, console, 2)
            for item in part.items:
                _line(item, console, 4, _DIM)
    if shown.unknowns:
        _heading("NOT RECOGNISED", console)
        for unknown in shown.unknowns:
            _unknown(unknown, console)
    _checks(shown, console)


def _checks(shown: View, console: Console) -> None:
    """What the logs, the absences, the gaps, the questions asked and the checks not run say."""
    _dim_section("CERTIFICATE TRANSPARENCY", shown.ct, console)
    if shown.absences:
        _heading("CHECKED AND NOT THERE", console)
        for a in shown.absences:
            _line(f"{a.asked}: {a.happened}", console, 2)
            for answer in a.answers:
                _line(answer, console, 4, _DIM)
    _dim_section("NOT CHECKED", [str(g) for g in shown.gaps], console)
    if shown.asked:
        _heading("WHAT WAS ASKED", console)
        _line(shown.asked_total, console, 2, _DIM)
        for record in shown.asked:
            _line(f"{record.where}: {record.counts}", console, 2, _DIM)
            for heading, names in record.names:
                _line(f"{heading}: {', '.join(names)}", console, 4, _DIM)
    if shown.off:
        _heading("NOT RUN", console)
        for off in shown.off:
            _line(f"{off.check}: {off.how}", console, 2, _DIM)


def _line(text: str | Text, console: Console, indent: int, style: str = "") -> None:
    """One line at `indent`, wrapped lines kept at the same indent."""
    body = text if isinstance(text, Text) else Text(text, style=style)
    console.print(Padding(body, (0, 0, 0, indent), expand=False))


def _heading(title: str, console: Console, style: str = "bold") -> None:
    console.print(Text(f"\n{title}", style=style))


def _dim_section(title: str, lines: tuple[str, ...] | list[str], console: Console) -> None:
    if lines:
        _heading(title, console)
        for line in lines:
            _line(line, console, 2, _DIM)


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
    for sentence in head.sentences if head.story else ():
        console.print(Text(sentence))


def _findings(shown: View, console: Console) -> None:
    if not shown.findings:
        return
    _heading("NEEDS ATTENTION", console)
    for f in shown.findings:
        marker = Text("● ", style=_SEVERITY_STYLE[f.severity])
        grid = Table.grid()
        grid.add_column(width=2)
        grid.add_column()
        grid.add_row(marker, Text(f.title, style="bold"))
        console.print(Padding(grid, (0, 0, 0, 2), expand=False))
        _line(f.detail, console, 4, _DIM)
        for record in f.records:
            _line(record, console, 6, _DIM)


def _services(services: tuple[ServiceView, ...], console: Console) -> None:
    """Each service as a block: its name, category and where, then one line per kind of record,
    wrapped at the indent it starts at, then its setup."""
    width = max([len("Setup"), *(len(k.label) for s in services for k in s.kinds)]) + 2
    for service in services:
        head = Text.assemble((service.name, "bold"), "  ", (service.category, _DIM))
        if service.where:
            head.append(f"  at {service.where}", style=_DIM)
        _line(head, console, 2)
        rows = Table.grid()
        rows.add_column(width=width, style=_DIM, no_wrap=True)
        rows.add_column(overflow="fold")
        for kind in service.kinds:
            rows.add_row(kind.label, kind.summary)
            for record in kind.records:
                rows.add_row("", Text(record, style=_DIM))
        if service.setup:
            rows.add_row("Setup", _setup(service.setup))
        console.print(Padding(rows, (0, 0, 0, 4), expand=False))


def _setup(clause: str) -> Text:
    """The setup clause without its leading word, coloured by whether it is complete."""
    said = clause.removeprefix("setup ")
    style = "green" if said == "complete" else "yellow"
    head, _, rest = said.partition(": ")
    text = Text(head, style=style)
    if rest:
        text.append(f": {rest}")
    return text


def _unknown(item: UnknownView, console: Console) -> None:
    """One unknown with its record, or one network's group: its count line, its ranges and
    addresses, and the records shown, with how many more there are."""
    where = f"  at {item.where}" if item.where else ""
    if item.grouped:
        _line(Text.assemble(item.label, (where, _DIM)), console, 2)
        _line(", ".join(item.values), console, 4, _DIM)
    else:
        _line(Text.assemble(f"{item.label}: {item.values[0]}", (where, _DIM)), console, 2)
    for record in item.records:
        _line(record, console, 4, _DIM)
    if item.more:
        _line(f"+ {item.more} more", console, 4, _DIM)
