"""Ways to show a SenderMap: a terminal view, Markdown to paste, JSON to process."""

from __future__ import annotations

from ..model import Checked


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
