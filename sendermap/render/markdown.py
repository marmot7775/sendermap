"""Markdown, for pasting the map into a ticket, a report or an email."""

from __future__ import annotations

from ..model import SenderMap, Service


def render(result: SenderMap) -> str:
    lines = [f"# Sendermap: {result.domain}", ""]
    lines.append(
        f"{len(result.senders)} sending services found from public records "
        f"({result.lookups} lookups)."
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
    return "\n".join(lines) + "\n"


def _row(service: Service, domain: str) -> str:
    claim = service.decided_by
    at = "" if claim.where == domain else f" at {claim.where}"
    return (
        f"| {service.name} | {service.category} | {service.tier.value} | "
        f"{claim.kind.value}{at}: `{claim.evidence}` |"
    )
