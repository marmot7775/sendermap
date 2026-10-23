"""Markdown, for pasting the map into a ticket, a report or an email: the View as headings, with
the senders in one table."""

from __future__ import annotations

from .view import SenderMap, ServiceView, UnknownView, View, view


def render(result: SenderMap, *, evidence: bool = False) -> str:
    """The map's View as Markdown."""
    return show(view(result, evidence=evidence))


def show(shown: View) -> str:
    """One View as Markdown, each section left out when it is empty."""
    lines = _head(shown)
    if shown.findings:
        lines += _section("Needs attention")
        for f in shown.findings:
            lines.append(f"- **{f.title}** ({f.severity}). {f.detail}")
            lines += [f"  - `{record}`" for record in f.records]
    lines += _senders(shown)
    if shown.reporting:
        lines += [*_section("Reports go to"), ", ".join(shown.reporting)]
    if shown.claimed:
        lines += _section("Claimed senders")
        for part in shown.claimed:
            lines.append(f"- **{part.heading}**")
            lines += [f"  - {item}" for item in part.items]
    if shown.unknowns:
        lines += _section("Not recognised")
        lines += [_unknown(u) for u in shown.unknowns]
    return "\n".join(lines + _checks(shown)) + "\n"


def _checks(shown: View) -> list[str]:
    """What the logs, the absences, the gaps and the questions asked say."""
    lines: list[str] = []
    if shown.ct:
        lines += [*_section("Certificate transparency"), *(f"- {line}" for line in shown.ct)]
    if shown.absences:
        lines += _section("Checked and not there")
        for a in shown.absences:
            lines.append(f"- {a.asked}: {a.happened}")
            lines += [f"  - `{answer}`" for answer in a.answers]
    if shown.gaps:
        lines += [*_section("Not checked"), *(f"- {g.asked}: {g.happened}" for g in shown.gaps)]
    if shown.asked:
        lines += _section("What was asked")
        lines += [f"- **{record.where}**: {record.counts}" for record in shown.asked]
    if shown.off:
        lines += [*_section("Not run"), *(f"- {o.check}: {o.how}" for o in shown.off)]
    if any(record.names for record in shown.asked):
        lines += _section("Appendix: names asked")
        for record in shown.asked:
            lines.append(f"- **{record.where}**")
            lines += [
                f"  - {heading}: {', '.join(f'`{n}`' for n in names)}"
                for heading, names in record.names
            ]
    return lines


def _section(title: str) -> list[str]:
    return ["", f"## {title}", ""]


def _head(shown: View) -> list[str]:
    head = shown.head
    lines = [f"# Sendermap: {head.domain}", "", head.summary()]
    return lines + (["", head.story] if head.story else [])


def _senders(shown: View) -> list[str]:
    """The senders table, one row per service, then each record in full when evidence is set."""
    services = [s for tier in shown.tiers for s in tier.services]
    if not services:
        return []
    lines = [
        *_section("Senders"),
        "| Service | Category | How sure | Evidence | Setup |",
        "|---|---|---|---|---|",
    ]
    lines += [_row(s) for s in services]
    if shown.evidence:
        lines += _section("Records")
        for service in services:
            lines.append(f"- **{service.name}**")
            for kind in service.kinds:
                lines.append(f"  - {kind.label}")
                lines += [f"    - `{record}`" for record in kind.records]
    return lines


def _row(service: ServiceView) -> str:
    name = f"{service.name} ({service.where})" if service.where else service.name
    evidence = "; ".join(map(str, service.kinds))
    cells = (name, service.category, service.tier, evidence, service.setup)
    return "| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |"


def _unknown(item: UnknownView) -> str:
    """One unknown with its record, or one network's group with its ranges and addresses and the
    records shown, with how many more there are."""
    at = f" at {item.where}" if item.where else ""
    values = ", ".join(f"`{v}`" for v in item.values)
    head = f"- {item.label}{at}: {values}" if item.grouped else f"- {item.label}: {values}{at}"
    if not item.grouped or not item.more:
        if len(item.records) == 1:
            return f"{head}, from `{item.records[0]}`"
        return "\n".join([head, *(f"  - `{record}`" for record in item.records)])
    return f"{head}, from `{item.records[0]}` + {item.more} more"
