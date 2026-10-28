"""Markdown, for pasting the map into a ticket, a report or an email: the terminal view's layout
in plain headings and lists.

The head says the domain, the tally and how the map was made, then the story. The sections
follow in SECTIONS' order under the names every view gives them. Records sit in code spans and
nothing is laid out as a table, so the text reads the same pasted as plain text.
"""

from __future__ import annotations

from collections.abc import Callable

from .view import SECTIONS, FindingView, SenderMap, ServiceView, UnknownView, View, view


def render(result: SenderMap, *, evidence: bool = False) -> str:
    """The map's View as Markdown."""
    return show(view(result, evidence=evidence))


def show(shown: View) -> str:
    """One View as Markdown: the head, then each section in SECTIONS' order, left out when it
    is empty."""
    lines = _head(shown)
    for key, name in SECTIONS:
        body = _SECTIONS[key](shown)
        if body:
            intro = [line for said in shown.intro(key) for line in (said, "")]
            lines += ["", f"## {name}", "", *intro, *body]
    return "\n".join(lines) + "\n"


def _code(text: str) -> str:
    """`text` as a code span, fenced with more backticks than it holds."""
    longest = 0
    current = 0
    for char in text:
        current = current + 1 if char == "`" else 0
        longest = max(longest, current)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _records(records: tuple[str, ...], indent: str) -> list[str]:
    return [f"{indent}- {_code(record)}" for record in records]


# ---------------------------------------------------------------- head


def _head(shown: View) -> list[str]:
    """The question the map answers, the answer in bold, then the story a sentence a
    paragraph."""
    head = shown.head
    answer = head.answer(len(shown.fixes))
    lines = [f"# {head.question}", *(["", f"**{answer}**"] if answer else [])]
    for sentence in head.lede:
        lines += ["", sentence]
    return lines


# ---------------------------------------------------------------- sections


def _glance(shown: View) -> list[str]:
    """One line per service: name, category and where, status and setup, then where reports
    go."""
    return [_glance_line(service) for service in shown.services]


def _glance_line(service: ServiceView) -> str:
    meta = service.category + (f", at {service.where}" if service.where else "")
    words, _ = service.glance
    said = service.status.lower() + (f"; {words}" if words else "")
    return f"- **{service.name}** ({meta}): {said}"


def _fixes(shown: View) -> list[str]:
    """The risks and warnings, numbered, each title with its severity, detail and records."""
    lines: list[str] = []
    for number, f in enumerate(shown.fixes, 1):
        lead = f"{number}. "
        indent = " " * len(lead)
        lines += [f"{lead}**{f.title}** ({f.severity})", "", f"{indent}{f.detail}"]
        if f.records:
            lines += ["", *_records(f.records, indent)]
        lines.append("")
    return lines[:-1]


def _notes(shown: View) -> list[str]:
    lines: list[str] = []
    for f in shown.notes:
        lines.append(_note(f))
        lines += _records(f.records, "  ")
    return lines


def _note(f: FindingView) -> str:
    return f"- **{f.title}**. {f.detail}"


def _evidence(shown: View) -> list[str]:
    """Each service under a heading of its own: category, status and where, one item per kind
    of record with each record under it when evidence is set, then its setup."""
    lines: list[str] = []
    for service in shown.services:
        meta = f"{service.category} · {service.status.lower()}"
        if service.where:
            meta += f" · at {service.where}"
        lines += [f"### {service.name}", "", meta, ""]
        for kind in service.kinds:
            lines.append(f"- {kind.label}: {kind.summary}")
            lines += _records(kind.records, "  ")
        if service.setup:
            lines.append(f"- Setup: {service.setup.removeprefix('setup ')}")
        lines.append("")
    return lines[:-1]


def _claimed(shown: View) -> list[str]:
    lines: list[str] = []
    for part in shown.claimed:
        lines.append(f"- **{part.heading}**")
        lines += [f"  - {item}" for item in part.items]
    return lines


def _unknowns(shown: View) -> list[str]:
    return [_unknown(u) for u in shown.unknowns]


def _unknown(item: UnknownView) -> str:
    """One unknown with its record, or one network's group with its ranges and addresses and the
    records shown, with how many more there are."""
    at = f" at {item.where}" if item.where else ""
    values = ", ".join(_code(v) for v in item.values)
    head = f"- {item.label}{at}: {values}" if item.grouped else f"- {item.label}: {values}{at}"
    if not item.grouped or not item.more:
        if len(item.records) == 1:
            return f"{head}, from {_code(item.records[0])}"
        return "\n".join([head, *_records(item.records, "  ")])
    return f"{head}, from {_code(item.records[0])} + {item.more} more"


def _ct(shown: View) -> list[str]:
    return [f"- {line}" for line in shown.ct]


def _absences(shown: View) -> list[str]:
    lines: list[str] = []
    for a in shown.absences:
        lines.append(f"- {a.asked}: {a.happened}")
        lines += _records(a.answers, "  ")
    return lines


def _how(shown: View) -> list[str]:
    """What was asked, what was not checked and what did not run, each under a label of its
    own, then every name asked when evidence is set."""
    lines = [shown.head.made()]
    if shown.asked:
        lines += ["", *(f"- At {record.where}: {record.counts}." for record in shown.asked)]
    if shown.gaps:
        lines += _part("Not checked", [f"- {g}" for g in shown.gaps], lines)
    if shown.off:
        lines += _part("Not run", [f"- {o}" for o in shown.off], lines)
    names = [
        f"- {record.where}, {heading}: {', '.join(_code(n) for n in shown_names)}"
        for record in shown.asked
        for heading, shown_names in record.names
    ]
    if names:
        lines += _part("Names asked", names, lines)
    return lines


def _part(title: str, items: list[str], before: list[str]) -> list[str]:
    """A part of How this was checked: its name and items, a blank line first when something
    precedes it."""
    return [*([""] if before else []), f"{title}:", "", *items]


_SECTIONS: dict[str, Callable[[View], list[str]]] = {
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
