"""The terminal view: the View in rich, laid out to be read top down.

The question the map answers and its answer in plain words, then each section under a plain name
with a line or two saying what it shows, then the records, dimmed, for a reader who wants them,
and last how the map was made.
"""

from __future__ import annotations

from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from .view import SECTIONS, FindingView, SenderMap, ServiceView, UnknownView, View, view

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
# A section's name and the plain lines under it.
Title = tuple[str, tuple[str, ...]]


def render(result: SenderMap, console: Console, *, evidence: bool = False) -> None:
    """Print the map's View to `console`."""
    show(view(result, evidence=evidence), console)


def show(shown: View, console: Console) -> None:
    """Print one View: the question and its answer, then each section in SECTIONS' order under
    its name and intro, left out when it is empty."""
    _head(shown, console)
    _story(shown, console)
    for key, name in SECTIONS:
        _SECTIONS[key](shown, (name, shown.intro(key)), console)


def _line(text: str | Text, console: Console, indent: int, style: str = "") -> None:
    """One line at `indent`, wrapped lines kept at the same indent."""
    body = text if isinstance(text, Text) else Text(text, style=style)
    console.print(Padding(body, (0, 0, 0, indent), expand=False))


def _heading(title: Title, console: Console) -> None:
    """The section's name, then its intro, the first line plain and the rest dimmed."""
    name, intro = title
    console.print(Text(f"\n{name}", style=_HEADING))
    for i, line in enumerate(intro):
        _line(line, console, 2, "" if i == 0 else _DIM)
    if intro:
        console.print()


# ---------------------------------------------------------------- head and glance


def _head(shown: View, console: Console) -> None:
    """The question the map answers, then the answer: how many services and what to fix."""
    head = shown.head
    console.print(Text(head.question, style=_HEADING))
    style = "bold yellow" if shown.fixes else "green" if head.senders else ""
    if answer := head.answer(len(shown.fixes)):
        _line(answer, console, 2, style)


def _story(shown: View, console: Console) -> None:
    """The story under the panel, a sentence a line, without what was not checked."""
    sentences = shown.head.lede
    if sentences:
        console.print()
    for sentence in sentences:
        _line(sentence, console, 2)


def _glance(shown: View, title: Title, console: Console) -> None:
    """One row per service: marker, name, category, status and setup. Where reports go is in
    the story above."""
    services = shown.services
    if not services:
        return
    _heading(title, console)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(style="bold", overflow="fold")
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


def _fixes(shown: View, title: Title, console: Console) -> None:
    """The risks and warnings, numbered."""
    if shown.fixes:
        _heading(title, console)
    for number, f in enumerate(shown.fixes, 1):
        _finding(f, f"{number:>2} ", console)


def _notes(shown: View, title: Title, console: Console) -> None:
    """The notes, unnumbered after what to fix."""
    if shown.notes:
        _heading(title, console)
    for f in shown.notes:
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


def _evidence(shown: View, title: Title, console: Console) -> None:
    """Each service as a block: name, category and status, one line per kind of record, then
    its setup."""
    services = shown.services
    if not services:
        return
    _heading(title, console)
    width = max([len("Setup"), *(len(k.label) for s in services for k in s.kinds)]) + 2
    for number, service in enumerate(services):
        _, style = _TIER_MARK.get(service.tier, ("●", ""))
        head = Text.assemble(
            (service.name, "bold"), ("  ·  ", _DIM), (service.category, _DIM), ("  ·  ", _DIM)
        )
        head.append(service.status.lower(), style=style)
        if service.where:
            head.append(f"  at {service.where}", style=_DIM)
        if number:
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


def _claimed(shown: View, title: Title, console: Console) -> None:
    if shown.claimed:
        _heading(title, console)
    for part in shown.claimed:
        _line(part.heading, console, 2)
        for item in part.items:
            _line(item, console, 4, _DIM)


def _unknowns(shown: View, title: Title, console: Console) -> None:
    if shown.unknowns:
        _heading(title, console)
    for unknown in shown.unknowns:
        _unknown(unknown, console, shown.evidence)


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


def _ct(shown: View, title: Title, console: Console) -> None:
    if shown.ct:
        _heading(title, console)
    for line in shown.ct:
        _line(line, console, 2, _DIM)


def _absences(shown: View, title: Title, console: Console) -> None:
    if shown.absences:
        _heading(title, console)
    for a in shown.absences:
        _line(f"{a.asked}: {a.happened}", console, 2)
        for answer in a.answers:
            _line(answer, console, 4, _DIM)


# ---------------------------------------------------------------- how the map was made


def _how(shown: View, title: Title, console: Console) -> None:
    """What was asked, what was not checked and what did not run, in one dimmed block. The
    names asked at each name sit under its count, not after the block."""
    lines: list[tuple[str, int]] = [(shown.head.made(), 2)]
    for record in shown.asked:
        lines.append((f"At {record.where}: {record.counts}.", 2))
        lines += [(f"{heading}: {', '.join(names)}", 4) for heading, names in record.names]
    lines += [(f"Not checked: {g}", 2) for g in shown.gaps]
    lines += [(f"Not run: {off}", 2) for off in shown.off]
    if not shown.evidence:
        lines.append(("Add --evidence to see every record behind each line.", 2))
    _heading(title, console)
    for line, indent in lines:
        _line(line, console, indent, _DIM)


_SECTIONS = {
    "glance": _glance,
    "fixes": _fixes,
    "notes": _notes,
    "evidence": _evidence,
    "claimed": _claimed,
    "unknowns": _unknowns,
    "ct": _ct,
    "absences": _absences,
    "how": _how,
}
