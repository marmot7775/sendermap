"""The terminal view: the View in rich, laid out to be read top down.

A panel with the domain and the count of things to fix, then the services at a glance, then what
to fix, then the evidence service by service, then what was not recognised, and last, dimmed, how
the map was made.
"""

from __future__ import annotations

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .view import FindingView, SenderMap, ServiceView, UnknownView, View, view

# The marker and colour of each tier, by the tier's name in the View.
_TIER_MARK = {
    "In use": ("●", "bold green"),
    "Configured": ("●", "bold cyan"),
    "Likely": ("◐", "bold yellow"),
    "Account only": ("○", "bright_black"),
}
_SEVERITY_STYLE = {"risk": "bold red", "warning": "bold yellow", "note": "bright_black"}
_DIM = "bright_black"
_HEADING = "bold bright_white"


def render(result: SenderMap, console: Console, *, evidence: bool = False) -> None:
    """Print the map's View to `console`."""
    show(view(result, evidence=evidence), console)


def show(shown: View, console: Console) -> None:
    """Print one View, each section left out when it is empty."""
    _head(shown, console)
    _story(shown, console)
    _glance(shown, console)
    _findings(shown, console)
    _evidence(shown, console)
    if shown.claimed:
        _heading("CLAIMED SENDERS", console)
        for part in shown.claimed:
            _line(part.heading, console, 2)
            for item in part.items:
                _line(item, console, 4, _DIM)
    if shown.unknowns:
        _heading("NOT RECOGNISED", console)
        for unknown in shown.unknowns:
            _unknown(unknown, console, shown.evidence)
    if shown.ct:
        _heading("CERTIFICATE LOGS", console)
        for line in shown.ct:
            _line(line, console, 2, _DIM)
    if shown.absences:
        _heading("CHECKED AND NOT THERE", console)
        for a in shown.absences:
            _line(f"{a.asked}: {a.happened}", console, 2)
            for answer in a.answers:
                _line(answer, console, 4, _DIM)
    _how(shown, console)


def _line(text: str | Text, console: Console, indent: int, style: str = "") -> None:
    """One line at `indent`, wrapped lines kept at the same indent."""
    body = text if isinstance(text, Text) else Text(text, style=style)
    console.print(Padding(body, (0, 0, 0, indent), expand=False))


def _heading(title: str, console: Console) -> None:
    console.print(Text(f"\n{title}", style=_HEADING))


# ---------------------------------------------------------------- head and glance


def _head(shown: View, console: Console) -> None:
    """The domain, how many services send as it and how many things need fixing, and how the
    map was made, in one panel."""
    head = shown.head
    count = head.senders
    senders = (
        f"{count} service{'s' if count != 1 else ''} send{'s' if count == 1 else ''} "
        "email as this domain"
        if count
        else "No sending service found"
    )
    fixes = len(shown.fixes)
    line = Text.assemble((head.domain, "bold"), "\n", senders)
    if fixes:
        line.append("   ·   ", style=_DIM)
        line.append(f"{fixes} thing{'s' if fixes != 1 else ''} to fix", style="bold yellow")
    elif count:
        line.append("   ·   ", style=_DIM)
        line.append("nothing to fix", style="green")
    how = (
        f"checked {head.checked_at} · {head.lookups} lookups in {head.elapsed:.1f} s "
        f"over {head.resolver}"
    )
    line.append(f"\n{how}", style=_DIM)
    console.print(Panel(line, border_style="cyan", expand=False, padding=(0, 2)))


def _story(shown: View, console: Console) -> None:
    """The story under the panel, a sentence a line. Its last sentence, what was not checked, is
    said in full under HOW THIS WAS CHECKED, so it is left out here, as the page mutes it."""
    sentences = [s for s in shown.head.sentences if not s.startswith("Not checked")]
    if sentences:
        console.print()
    for sentence in sentences:
        _line(sentence, console, 2)


def _glance(shown: View, console: Console) -> None:
    """One row per service: marker, name, category, status and setup, then where reports go."""
    services = shown.services
    if not services:
        return
    _heading("AT A GLANCE", console)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(style=_DIM, no_wrap=True)
    grid.add_column(no_wrap=True)
    grid.add_column()
    for service in services:
        mark, style = _TIER_MARK.get(service.tier, ("●", ""))
        name = f"{service.name} ({service.where})" if service.where else service.name
        grid.add_row(
            Text(mark, style=style),
            name,
            service.category,
            Text(service.status, style=style),
            _setup_glance(service),
        )
    console.print(Padding(grid, (0, 0, 0, 2), expand=False))
    if shown.reporting:
        _line(f"Reports go to {', '.join(shown.reporting)}.", console, 2, _DIM)


_GLANCE = {
    "complete": ("✓ ", "green"),
    "incomplete": ("⚠ ", "yellow"),
    "unchecked": ("? ", _DIM),
    "basis": ("", _DIM),
}


def _setup_glance(service: ServiceView) -> Text:
    """The setup in two or three words, or what the tier rests on for a weak one."""
    words, state = service.glance
    mark, style = _GLANCE.get(state, ("", ""))
    return Text(f"{mark}{words}", style=style)


# ---------------------------------------------------------------- findings


def _findings(shown: View, console: Console) -> None:
    """Risks and warnings numbered under FIX THESE, notes after them unnumbered."""
    fixes, notes = shown.fixes, shown.notes
    if fixes:
        _heading("FIX THESE", console)
        for number, f in enumerate(fixes, 1):
            _finding(f, f"{number:>2} ", console)
    if notes:
        _heading("NOTES", console)
        for f in notes:
            _finding(f, " · ", console)


def _finding(f: FindingView, lead: str, console: Console) -> None:
    style = _SEVERITY_STYLE[f.severity]
    grid = Table.grid()
    grid.add_column(width=len(lead) + 2, no_wrap=True)
    grid.add_column()
    marker = Text(lead, style=_DIM)
    fix = f.severity != "note"
    marker.append("▲ " if fix else "", style=style)
    title_style = "bold" if fix else ""
    grid.add_row(marker, Text(f.title, style=title_style))
    grid.add_row("", Text(f.detail, style=_DIM))
    for record in f.records:
        grid.add_row("", Padding(Text(record, style=_DIM), (0, 0, 0, 2)))
    console.print(Padding(grid, (0, 0, 0, 1), expand=False))


# ---------------------------------------------------------------- evidence


def _evidence(shown: View, console: Console) -> None:
    """Each service as a block: name, category and status, one line per kind of record, then
    its setup."""
    services = shown.services
    if not services:
        return
    _heading("EVIDENCE, SERVICE BY SERVICE", console)
    width = max([len("Setup"), *(len(k.label) for s in services for k in s.kinds)]) + 2
    for service in services:
        _, style = _TIER_MARK.get(service.tier, ("●", ""))
        head = Text.assemble(
            (service.name, "bold"), ("  ·  ", _DIM), (service.category, _DIM), ("  ·  ", _DIM)
        )
        head.append(service.status.lower(), style=style)
        if service.where:
            head.append(f"  at {service.where}", style=_DIM)
        console.print()
        _line(head, console, 2)
        rows = Table.grid(padding=(0, 1))
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


def _unknown(item: UnknownView, console: Console, evidence: bool) -> None:
    """One unknown in a line, or one network's group with its ranges and addresses; the records
    under it when evidence is set, or always for a group, whose values alone do not say where."""
    where = f"  at {item.where}" if item.where else ""
    if item.grouped:
        _line(Text.assemble(item.label, (where, _DIM)), console, 2)
        _line(", ".join(item.values), console, 4, _DIM)
    else:
        line = Text.assemble((f"{item.label}: ", _DIM), item.values[0], (where, _DIM))
        _line(line, console, 2)
    if evidence or item.grouped:
        for record in item.records:
            _line(record, console, 4, _DIM)
        if item.more:
            _line(f"+ {item.more} more", console, 4, _DIM)


# ---------------------------------------------------------------- how the map was made


def _how(shown: View, console: Console) -> None:
    """What was asked, what was not checked and what did not run, in one dimmed block."""
    lines: list[str] = []
    if shown.asked:
        lines.append(f"Asked {shown.asked_total}:")
        lines += [f"  {record.where}: {record.counts}" for record in shown.asked]
    lines += [f"Not checked: {g}" for g in shown.gaps]
    lines += [f"Not run: {off.check}: {off.how}" for off in shown.off]
    if not shown.evidence:
        lines.append("Add --evidence to see every record behind each line.")
    if not lines:
        return
    _heading("HOW THIS WAS CHECKED", console)
    for line in lines:
        _line(line.lstrip(), console, 4 if line.startswith("  ") else 2, _DIM)
    for record in shown.asked:
        for heading, names in record.names:
            _line(f"{record.where}, {heading}: {', '.join(names)}", console, 4, _DIM)
