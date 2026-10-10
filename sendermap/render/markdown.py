"""Markdown, for pasting the map into a ticket, a report or an email."""

from __future__ import annotations

from datetime import UTC

from ..model import SenderMap, Service
from . import asked, asked_in_full


def render(result: SenderMap) -> str:
    lines = [f"# Sendermap: {result.domain}", ""]
    checked = result.run.checked_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(
        f"{len(result.senders)} sending services found from public records checked {checked} "
        f"({result.run.lookups} lookups)."
    )
    lines += ["", "| Service | Category | How sure | Evidence |", "|---|---|---|---|"]
    lines += [_row(s, result.domain) for s in result.senders]
    if result.reporting:
        lines += ["", "**Reports go to:** " + ", ".join(s.name for s in result.reporting)]
    if result.findings:
        lines += ["", "## Needs attention", ""]
        lines += [f"- **{f.title}** ({f.severity.value}). {f.detail}" for f in result.findings]
    if result.unknowns:
        lines += ["", "## Not recognised", ""]
        lines += [
            f"- {u.what}: `{u.value}`" + ("" if u.where == result.domain else f" at {u.where}")
            for u in result.unknowns
        ]
    if result.gaps:
        lines += ["", "## Not checked", ""]
        lines += [f"- {g.asked}: {g.happened}" for g in result.gaps]
    if result.checked:
        lines += ["", "## What was asked", ""]
        for record in result.checked:
            lines.append(f"- **{record.where}**: {asked(record)}")
            lines += [
                f"  - {heading}: {', '.join(f'`{n}`' for n in names)}"
                for heading, names in asked_in_full(record)
            ]
    return "\n".join(lines) + "\n"


def _row(service: Service, domain: str) -> str:
    claim = service.decided_by
    at = "" if claim.where == domain else f" at {claim.where}"
    return (
        f"| {service.name} | {service.category} | {service.tier.value} | "
        f"{claim.kind.value}{at}: `{claim.evidence}` |"
    )
