"""Markdown, for pasting the map into a ticket, a report or an email."""

from __future__ import annotations

from datetime import UTC

from ..model import SenderMap, Service, Unknown
from ..setup import line
from . import NetworkGroup, asked, asked_in_full, claimed_parts, ct_lines, grouped_unknowns


def render(result: SenderMap, *, evidence: bool = False) -> str:
    lines = [f"# Sendermap: {result.domain}", ""] + ([result.story, ""] if result.story else [])
    checked = result.run.checked_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(
        f"{len(result.senders)} sending services found from public records checked {checked} "
        f"({result.run.lookups} lookups)."
    )
    lines += ["", "| Service | Category | How sure | Evidence |", "|---|---|---|---|"]
    lines += [_row(s, result.domain) for s in result.senders]
    if setups := [s for s in result.senders if s.setups]:
        lines += ["", "## Setups", ""]
        for service in setups:
            lines.append(f"- **{service.name}**")
            lines += [f"  - {line(setup)}" for setup in service.setups]
    if result.reporting:
        lines += ["", "**Reports go to:** " + ", ".join(s.name for s in result.reporting)]
    lines += _claimed(result)
    if result.findings:
        lines += ["", "## Needs attention", ""]
        lines += [f"- **{f.title}** ({f.severity.value}). {f.detail}" for f in result.findings]
    if result.unknowns:
        lines += ["", "## Not recognised", ""]
        for item in grouped_unknowns(result.unknowns):
            lines += _unknown(item, result.domain, evidence)
    if ct := ct_lines(result):
        lines += ["", "## Certificate transparency", ""]
        lines += [f"- {line}" for line in ct]
    if result.absences:
        lines += ["", "## Checked and not there", ""]
        for a in result.absences:
            lines.append(f"- {a.asked}: {a.happened}")
            lines += [f"  - `{e}`" for e in a.evidence]
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


def _claimed(result: SenderMap) -> list[str]:
    """The services the client claimed against the map, in four parts; nothing when none were."""
    if not result.reconciliation:
        return []
    lines = ["", "## Claimed senders", ""]
    for heading, items in claimed_parts(result.reconciliation):
        lines.append(f"- **{heading}**")
        lines += [f"  - {item}" for item in items]
    return lines


def _row(service: Service, domain: str) -> str:
    claim = service.decided_by
    at = "" if claim.where == domain else f" at {claim.where}"
    via = "".join(f" via `{e}`" for e in claim.supporting)
    cell = f"{claim.kind.value}{at}: `{claim.evidence}`{via}".replace("|", "\\|")
    return f"| {service.name} | {service.category} | {service.tier or ''} | {cell} |"


def _unknown(item: Unknown | NetworkGroup, domain: str, evidence: bool) -> list[str]:
    """One unknown with its record, or one network's group with its ranges and addresses and the
    first record, or every record when `evidence` is set."""
    at = "" if item.where == domain else f" at {item.where}"
    if isinstance(item, Unknown):
        return [f"- {item.what}: `{item.value}`{at}, from `{item.evidence}`"]
    cidrs = ", ".join(f"`{cidr}`" for cidr, _ in item.members)
    if evidence:
        return [f"- {item.heading()}{at}: {cidrs}"] + [
            f"  - `{u.evidence}`" for _, u in item.members
        ]
    more = len(item.members) - 1
    return [f"- {item.heading()}{at}: {cidrs}, from `{item.members[0][1].evidence}` + {more} more"]
