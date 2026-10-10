"""Ways to show a SenderMap: a terminal view, Markdown to paste, JSON to process."""

from __future__ import annotations

from ..model import CertificateEvidence, Checked, CtStatus, SenderMap


def asked(checked: Checked) -> str:
    """What was asked at one name, counted: "172 DKIM selectors, 23 labels, 2 pages"."""
    counts = (
        (len(checked.dkim_selectors), "DKIM selector"),
        (len(checked.labels), "CNAME label"),
        (len(checked.pages), "page"),
    )
    return ", ".join(f"{n} {what}{'s' if n != 1 else ''}" for n, what in counts if n) or "none"


def asked_in_full(checked: Checked) -> list[tuple[str, tuple[str, ...]]]:
    """(heading, names) for each list that has anything in it."""
    lists = (
        ("Pages", checked.pages),
        ("CNAME labels", checked.labels),
        ("DKIM selectors", checked.dkim_selectors),
    )
    return [(heading, names) for heading, names in lists if names]


def ct_lines(result: SenderMap) -> list[str]:
    """The certificate transparency section as plain lines; empty when CT was off."""
    if result.ct.status is CtStatus.OFF:
        return []
    summary = result.ct
    if summary.status is CtStatus.UNAVAILABLE:
        return ["crt.sh was unavailable, so no names from certificate logs were checked."]
    lines = [f"{summary.logged} names logged ({summary.status}); {summary.resolved} resolved now."]
    current = [
        (s.name, c)
        for s in result.services
        for c in s.claims
        if isinstance(c.evidence, CertificateEvidence)
    ]
    lines += [f"Current: {name} at {c.where} ({c.kind}): {c.evidence.value}" for name, c in current]
    if not current:
        lines.append("Current: no logged name points at a known service.")
    lines += [
        f"Possible past vendor: {h.service} at {h.evidence.name}: {h.evidence.value} "
        "(the name no longer resolves)"
        for h in result.historical
    ]
    if gone := summary.gone_unnamed:
        names = (
            "name no longer resolves and names" if gone == 1 else "names no longer resolve and name"
        )
        lines.append(f"{gone} other logged {names} no service.")
    return lines
