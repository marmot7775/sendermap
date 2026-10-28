"""HTML for the web page: the View as a fragment the page sets as it is.

The fragment holds no html, head or body tags. Every string that came from DNS or a web page
passes through html.escape, attribute values too, so the page adds nothing from the map as
markup of its own. Each service's records in full, and the names asked, sit inside details
elements; the lines outside them are the ones the views show without evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from html import escape

from .view import (
    SECTIONS,
    AskedView,
    GapGroup,
    Head,
    OffView,
    SenderMap,
    ServiceView,
    View,
    listed,
    view,
)

_NOT_SLUG = re.compile(r"[^a-z0-9]")
_DECIDER = ' class="decider"'  # the kind line that holds the deciding claim, always the first


def html(result: SenderMap) -> str:
    """The map's View, with every record and name asked, as an HTML fragment."""
    return show(view(result, evidence=True))


def show(shown: View) -> str:
    """One View as an HTML fragment: the head, then each section in SECTIONS' order, left out
    when it is empty."""
    return _head(shown) + "".join(
        _with_intro(_SECTIONS[key](shown, name), shown.intro(key)) for key, name in SECTIONS
    )


def _with_intro(section: str, intro: tuple[str, ...]) -> str:
    """A rendered section with its intro under the title: the first line as a paragraph, the
    rest as a muted key."""
    if not section or not intro:
        return section
    lines = [f'<p class="section-intro">{_e(intro[0])}</p>']
    if intro[1:]:
        lines += ['<ul class="section-key">', *(f"<li>{_e(i)}</li>" for i in intro[1:]), "</ul>"]
    head, sep, rest = section.partition("</h3>\n")
    return head + sep + "\n".join(lines) + "\n" + rest


def slug(name: str) -> str:
    """A service name as a row's id suffix: lowercased, anything outside a to z and 0 to 9 a
    hyphen. "Customer.io" is "customer-io"."""
    return _NOT_SLUG.sub("-", name.lower())


# ---------------------------------------------------------------- building blocks


def _e(text: str) -> str:
    return escape(text, quote=True)


def _section(title: str, kind: str, body: Iterable[str]) -> str:
    lines = [
        f'<section class="view-section {_e(kind)}">',
        f'<h3 class="section-title">{_e(title)}</h3>',
        *body,
        "</section>",
    ]
    return "\n".join(lines) + "\n"


def _details(summary: str, kind: str, body: Iterable[str]) -> list[str]:
    return [f'<details class="{_e(kind)}"><summary>{_e(summary)}</summary>', *body, "</details>"]


def _records(records: Iterable[str]) -> list[str]:
    return [
        '<ul class="records">',
        *(f'<li class="ev mono">{_e(r)}</li>' for r in records),
        "</ul>",
    ]


def _list(title: str, kind: str, lines: Iterable[str]) -> str:
    items = [f"<li>{_e(line)}</li>" for line in lines]
    if not items:
        return ""
    return _section(title, kind, ['<ul class="gaps">', *items, "</ul>"])


# ---------------------------------------------------------------- sections


def _head(shown: View) -> str:
    """The question the map answers, the answer, how the map was made, then the story in the
    lead block."""
    head = shown.head
    state = "to-fix" if shown.fixes else "no-fix" if head.senders else ""
    answer = head.answer(len(shown.fixes))
    lines = [
        '<header class="view-head">',
        f"<h2>{_e(head.question)}</h2>",
        *(
            [f'<p class="summary"><strong class="{state}">{_e(answer)}</strong></p>']
            if answer
            else []
        ),
        f'<p class="checked">{_e(head.made())}</p>',
        "</header>",
    ]
    if head.story:
        lines += ['<div class="lead">', *_story(head), "</div>"]
    return "\n".join(lines) + "\n"


def _story(head: Head) -> list[str]:
    """The story one paragraph per sentence, the Not checked one muted. A story the rules did not
    write comes as one string and stays one paragraph."""
    said = head.sentences or (head.story,)
    paragraphs = [
        f'<p class="story-muted">{_e(s)}</p>' if s.startswith("Not checked") else f"<p>{_e(s)}</p>"
        for s in said
    ]
    return ['<div class="story">', *paragraphs, "</div>"]


_STATE_MARK = {"complete": "✓ ", "incomplete": "⚠ ", "unchecked": "? ", "basis": ""}


def _glance(shown: View, title: str) -> str:
    """One table row per service, each name linking to its evidence, then where reports go."""
    if not shown.services:
        return ""
    body = [
        '<table class="glance">',
        "<thead><tr><th>Service</th><th>Category</th><th>Status</th><th>Setup</th></tr></thead>",
        "<tbody>",
    ]
    for service in shown.services:
        key = slug(service.tier)
        words, state = service.glance
        name = service.name + (f" ({service.where})" if service.where else "")
        body += [
            "<tr>",
            f'<td class="name"><span class="dot {_e(key)}"></span>'
            f'<a href="#service-{_e(slug(service.name))}">{_e(name)}</a></td>',
            f'<td class="category">{_e(service.category)}</td>',
            f'<td><span class="badge b-{_e(key)}">{_e(service.status)}</span></td>',
            f'<td class="state {_e(state)}">{_e(_STATE_MARK.get(state, "") + words)}</td>',
            "</tr>",
        ]
    body += ["</tbody>", "</table>"]
    return _section(title, "glance", body)


def _fixes(shown: View, title: str) -> str:
    """The risks and warnings, numbered."""
    findings = shown.fixes
    if not findings:
        return ""
    body = ['<ol class="fixes">']
    for f in findings:
        body += [
            f'<li class="finding {_e(f.severity)}">',
            f"<h4>{_e(f.title)}</h4>",
            f"<p>{_e(f.detail)}</p>",
        ]
        if f.records:
            body += _details("Records", "records", _records(f.records))
        body.append("</li>")
    body.append("</ol>")
    return _section(title, "attention", body)


def _notes(shown: View, title: str) -> str:
    """The notes: worth knowing, nothing to fix."""
    findings = shown.notes
    if not findings:
        return ""
    body = ['<ul class="notes">']
    for f in findings:
        body += [f"<li><strong>{_e(f.title)}</strong>. {_e(f.detail)}"]
        if f.records:
            body += _details("Records", "records", _records(f.records))
        body.append("</li>")
    body.append("</ul>")
    return _section(title, "notes", body)


def _evidence(shown: View, title: str) -> str:
    services = shown.services
    if not services:
        return ""
    rows = [line for service in services for line in _row(service)]
    return _section(title, "tier", ['<div class="rows">', *rows, "</div>"])


def _row(service: ServiceView) -> list[str]:
    """One service as a row: name, category and where, tier badge, then the deciding kind with
    the other kinds and the setup in one clause under it, and every record, with the setup item
    by item, inside All records."""
    badge = f"b-{slug(service.tier)}"
    meta = service.category + (f", at {service.where}" if service.where else "")
    first, rest = service.kinds[:1], service.kinds[1:]
    lines = [
        f'<article class="row" id="service-{_e(slug(service.name))}">',
        f"<h4>{_e(service.name)}</h4>",
        f'<p class="meta">{_e(meta)}</p>',
        f'<span class="badge {_e(badge)}">{_e(service.status)}</span>',
        '<div class="row-body">',
        *(f"<p{_DECIDER}>{_kind_line(k.label, k.summary)}</p>" for k in first),
    ]
    if rest:
        lines += [
            '<ul class="claims">',
            *(f"<li>{_kind_line(k.label, k.summary)}</li>" for k in rest),
            "</ul>",
        ]
    if service.brief:
        lines.append(f'<p class="setup">{_e(service.brief)}</p>')
    full: list[str] = []
    for kind in service.kinds:
        full += [f'<p class="kind">{_e(kind.label)}</p>', *_records(kind.records)]
    if service.setup and service.setup != service.brief:
        full.append(f'<p class="setup">{_e(service.setup)}</p>')
    return [*lines, *_details("All records", "records", full), "</div>", "</article>"]


def _kind_line(label: str, summary: str) -> str:
    return f'<span class="kind">{_e(label)}</span>: {_e(summary)}'


def _claimed(shown: View, title: str) -> str:
    if not shown.claimed:
        return ""
    body: list[str] = []
    for part in shown.claimed:
        body += [f"<h4>{_e(part.heading)}</h4>", '<ul class="gaps">']
        body += [f"<li>{_e(item)}</li>" for item in part.items]
        body.append("</ul>")
    return _section(title, "claimed", body)


def _unknowns(shown: View, title: str) -> str:
    if not shown.unknowns:
        return ""
    body = ['<ul class="unknowns">']
    for item in shown.unknowns:
        at = f" at {_e(item.where)}" if item.where else ""
        values = f'<span class="mono">{_e(", ".join(item.values))}</span>'
        head = (
            f"{_e(item.label)}{at}: {values}" if item.grouped else f"{_e(item.label)}: {values}{at}"
        )
        first, extra = item.records[:1], item.records[1:]
        body += [f"<li>{head}", *(f'<span class="ev mono">{_e(r)}</span>' for r in first)]
        if extra:
            more = f"{len(extra)} more record{'s' if len(extra) != 1 else ''}"
            body += _details(more, "records", _records(extra))
        body.append("</li>")
    body.append("</ul>")
    return _section(title, "unknowns", body)


def _ct(shown: View, title: str) -> str:
    return _list(title, "ct", shown.ct)


def _absences(shown: View, title: str) -> str:
    if not shown.absences:
        return ""
    body = ['<ul class="gaps absences">']
    for a in shown.absences:
        answers = "".join(f'<span class="ev mono">{_e(answer)}</span>' for answer in a.answers)
        body.append(f'<li><span class="mono">{_e(a.asked)}</span>: {_e(a.happened)}{answers}</li>')
    body.append("</ul>")
    return _section(title, "absences", body)


def _how(shown: View, title: str) -> str:
    """What was asked, not checked and not run, closed under one summary line."""
    gaps = _gaps(shown.gaps, shown.off)
    asked = _asked(shown.asked, shown.asked_total)
    if not gaps and not asked:
        return ""
    parts = [shown.asked_total] if shown.asked_total else []
    skipped = len(shown.gaps) + len(shown.off)
    if skipped:
        parts.append(f"{skipped} thing{'s' if skipped != 1 else ''} not checked")
    summary = " · ".join(parts) or "Details"
    body = [*gaps, *asked]
    return _section(title, "how-checked", _details(summary, "how", body))


def _gaps(gaps: tuple[GapGroup, ...], off: tuple[OffView, ...]) -> list[str]:
    if not gaps and not off:
        return []
    items = [f"<li>{_gap(g)}</li>" for g in gaps]
    items += [f"<li>{_e(str(o))}</li>" for o in off]
    return ["<h4>Not checked</h4>", '<ul class="gaps">', *items, "</ul>"]


def _gap(group: GapGroup) -> str:
    """One group as a line of prose with only the names in mono."""
    names = listed(f'<span class="mono">{_e(n)}</span>' for n in group.places())
    where = f" at {names}" if group.named else ""
    return f"{_e(group.asked)}{where}: {_e(group.outcome())}"


def _asked(asked: tuple[AskedView, ...], total: str) -> list[str]:
    """What was asked in all, then at each name, counted, with every name inside Names asked."""
    if not asked:
        return []
    counts = [
        f'<li>At <span class="mono">{_e(a.where)}</span>: {_e(a.counts)}.</li>' for a in asked
    ]
    body = ["<h4>What was asked</h4>", f'<p class="asked-total">{_e(total)}</p>']
    body += ['<ul class="gaps">', *counts, "</ul>"]
    names: list[str] = []
    for a in asked:
        if not a.names:
            continue
        names += [f'<h4 class="mono">{_e(a.where)}</h4>', "<ul>"]
        for heading, shown in a.names:
            joined = _e(", ".join(shown))
            names.append(
                f'<li>{_e(heading)} ({len(shown)}): <span class="mono">{joined}</span></li>'
            )
        names.append("</ul>")
    if names:
        body += _details("Names asked", "asked", names)
    return body


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
