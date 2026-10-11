"""Ways to show a SenderMap: a terminal view, Markdown to paste, JSON to process."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..model import CertificateEvidence, Checked, CtStatus, SenderMap, Unknown

# How sources/networks.py writes a range whose network it named: "<range> (<ASN>, <name>)",
# with "; listed by <services>" before the closing bracket when services publish the range.
# app.js reads the same shape with the same pattern.
NETWORK_VALUE = r"^(\S+) \((AS\d+), (.+?)(?:; listed by (.+))?\)$"
_NETWORK_VALUE = re.compile(NETWORK_VALUE)
_IP_KINDS = {"IP range in SPF": 0, "IP address in SPF": 1}


@dataclass(frozen=True, slots=True)
class NetworkGroup:
    """The unrecognised IP ranges and addresses at one name that one network announces, under one
    owner name and one list of publishers. Each Unknown is kept whole, with its evidence."""

    asn: str
    name: str
    listed: str
    where: str
    members: tuple[tuple[str, Unknown], ...]  # (the range or address, the Unknown that shows it)

    def heading(self) -> str:
        """The group's line: "2 ranges and 1 address in AS16509 (Amazon Web Services)", with
        the services that publish them after a semicolon."""
        counts = [0, 0]
        for _, u in self.members:
            counts[_IP_KINDS[u.what]] += 1
        ranges, addresses = counts
        parts = [f"{ranges} range{'s' if ranges != 1 else ''}"] if ranges else []
        if addresses:
            parts.append(f"{addresses} address{'es' if addresses != 1 else ''}")
        listed = f"; listed by {self.listed}" if self.listed else ""
        return f"{' and '.join(parts)} in {self.asn} ({self.name}){listed}"


def grouped_unknowns(unknowns: tuple[Unknown, ...]) -> list[Unknown | NetworkGroup]:
    """The unknowns in their order, with the IP ranges and addresses that share a network, an
    owner name, a list of publishers and a name gathered into one group where the first of them
    stood. A range with no network, one alone in its network, and anything that is not an IP
    range stay as they are."""
    keyed: dict[tuple[str, str, str, str], list[tuple[str, Unknown]]] = {}
    order: list[Unknown | tuple[str, str, str, str]] = []
    for u in unknowns:
        match = _NETWORK_VALUE.match(u.value) if u.what in _IP_KINDS else None
        if match is None:
            order.append(u)
            continue
        cidr, asn, name, listed = match.groups()
        key = (asn, name, listed or "", u.where)
        if key not in keyed:
            keyed[key] = []
            order.append(key)
        keyed[key].append((cidr, u))
    out: list[Unknown | NetworkGroup] = []
    for item in order:
        if isinstance(item, Unknown):
            out.append(item)
        elif len(members := keyed[item]) == 1:
            out.append(members[0][1])
        else:
            out.append(NetworkGroup(*item, members=tuple(members)))
    return out


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
