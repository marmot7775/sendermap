"""Selector dictionary for Sendermap.

A DKIM selector cannot be listed from DNS, so Sendermap probes a
dictionary of candidates. Every candidate carries its provenance:
the vendor it points to, how that knowledge was obtained, and a live
domain that publishes it. Rules are data, kept in each vendor's block
of data/vendors.json, so the dictionary can be reviewed and
contributed to without touching Python.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import date
from enum import Enum
from functools import cache
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Any, Protocol


class Source(Enum):
    """How a rule's selector names are known."""

    VENDOR_DOCS = "vendor_docs"
    AGGREGATE_REPORT = "aggregate_report"
    PATTERN = "pattern"


class Shape(Protocol):
    """Anything that expands into selector names."""

    def expand(self) -> Iterator[str]: ...


@dataclass(frozen=True, slots=True)
class Fixed:
    """An explicit set of names."""

    names: tuple[str, ...]

    def expand(self) -> Iterator[str]:
        return iter(self.names)


@dataclass(frozen=True, slots=True)
class Numbered:
    """A prefix followed by 1 through stop: selector1, selector2."""

    prefix: str
    stop: int

    def expand(self) -> Iterator[str]:
        return (f"{self.prefix}{n}" for n in range(1, self.stop + 1))


@dataclass(frozen=True, slots=True)
class Hints:
    """What a vendor's customers publish elsewhere in DNS.

    mx holds hostname suffixes found in the vendor's MX records; spf holds
    include domains the vendor tells customers to add. Both are lowercase.
    """

    mx: tuple[str, ...] = ()
    spf: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.mx or self.spf)

    def matches(self, mx_hosts: frozenset[str], spf_includes: frozenset[str]) -> bool:
        """True when any MX host ends in a hint suffix or any include is a hint domain.

        Both arguments must already be lowercase with no trailing dot. A suffix
        matches on a label boundary, so google.com matches aspmx.l.google.com
        but not notgoogle.com.
        """
        return any(
            host == suffix or host.endswith("." + suffix) for host in mx_hosts for suffix in self.mx
        ) or not spf_includes.isdisjoint(self.spf)


@dataclass(frozen=True, slots=True)
class Proof:
    """A live domain seen publishing one of a rule's selectors.

    record is the name as found, such as k2._domainkey.example.com; date is the
    day it was checked, as YYYY-MM-DD.
    """

    domain: str
    record: str
    date: str


@dataclass(frozen=True, slots=True)
class Rule:
    """What a vendor names its selectors, how we know, and where it was seen."""

    vendor: str
    shape: Shape
    source: Source
    proof: Proof
    reference: str | None = None
    hints: Hints = Hints()
    # Backs the hints, not the names: the page that lists a vendor's MX and SPF values is
    # rarely the page that lists its selectors.
    hints_reference: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        where = _where(self.vendor, self.shape)
        if self.source is Source.VENDOR_DOCS and _missing(self.reference):
            raise ValueError(f"{where}: vendor docs claimed, no reference given")
        cited = bool(self.hints_reference) and not any(map(_missing, self.hints_reference or ()))
        if not self.hints.empty and not cited:
            raise ValueError(f"{where}: hints given, no hints_reference")
        for field in ("domain", "record", "date"):
            if _missing(getattr(self.proof, field)):
                raise ValueError(f"{where}: proof has no {field}")
        try:
            date.fromisoformat(self.proof.date)
        except ValueError:
            raise ValueError(f"{where}: proof date {self.proof.date!r} is not YYYY-MM-DD") from None
        domain = _normalise(self.proof.domain)
        records = {f"{name}._domainkey.{domain}" for name in self.shape.expand()}
        if _normalise(self.proof.record) not in records:
            raise ValueError(f"{where}: proof record {self.proof.record!r} names none of these")


@dataclass(frozen=True, slots=True)
class Selector:
    """One probe candidate with its provenance attached."""

    name: str
    vendor: str
    source: Source
    reference: str | None
    proof: Proof


def _parse_vendor(vendor: str, block: Mapping[str, Any]) -> Iterator[Rule]:
    """Build a Rule from each selectors entry in one vendor block.

    Hints belong to the vendor, so every rule from the block carries the same ones.
    """
    hints_reference = block.get("hints_reference")
    if isinstance(hints_reference, str):
        raise ValueError(f"{vendor}: hints_reference must be a list, even with one URL")
    hint_spec = block.get("hints") or {}
    hints = Hints(**{key: tuple(map(_normalise, names)) for key, names in hint_spec.items()})
    for raw in block.get("selectors", ()):
        shape = _parse_shape(vendor, raw["shape"])
        proof = raw.get("proof")
        if not proof:
            raise ValueError(f"{_where(vendor, shape)}: no proof")
        reference = raw.get("reference")
        yield Rule(
            vendor=vendor,
            shape=shape,
            source=Source(raw["source"]),
            proof=Proof(proof.get("domain"), proof.get("record"), proof.get("date")),
            reference=None if _missing(reference) else reference,
            hints=hints,
            hints_reference=None if hints_reference is None else tuple(hints_reference),
        )


def _parse_shape(vendor: str, spec: Mapping[str, Any]) -> Shape:
    """Build a Shape from a rule's shape mapping. Names are lowercased here, once."""
    match spec["kind"]:
        case "fixed":
            return Fixed(tuple(name.lower() for name in spec["names"]))
        case "numbered":
            return Numbered(spec["prefix"].lower(), spec["stop"])
        case kind:
            raise ValueError(f"{vendor}: unknown shape kind {kind!r}")


def _normalise(name: str) -> str:
    """Lowercase a DNS name and drop any trailing dot."""
    return name.lower().rstrip(".")


def _missing(text: str | None) -> bool:
    """True for None, an empty string, or only whitespace."""
    return text is None or not text.strip()


def _where(vendor: str, shape: Shape) -> str:
    """Vendor and selector names, for error messages: Mailchimp k1, k3."""
    return f"{vendor} {', '.join(shape.expand())}"


# Found by package path, not the working directory, so the rules load the same from an
# installed wheel as from a checkout.
VENDORS_FILE = resources.files("sendermap").joinpath("data/vendors.json")


@cache
def load_rules(path: Traversable = VENDORS_FILE) -> tuple[Rule, ...]:
    """Read every vendor's selector rules; the vendors shipped with Sendermap by default.

    Cached per path, so a process reads each file once. Rules are frozen, so sharing is safe.
    """
    vendors: dict[str, Mapping[str, Any]] = json.loads(path.read_text(encoding="utf-8"))["vendors"]
    return tuple(rule for vendor, block in vendors.items() for rule in _parse_vendor(vendor, block))


def build_dictionary(rules: Iterable[Rule]) -> dict[str, tuple[Selector, ...]]:
    """Expand rules into candidates keyed by name.

    A name claimed by several vendors keeps every claim. A collision
    is a fact about the world; the caller decides what to do with it.
    """
    claims: defaultdict[str, list[Selector]] = defaultdict(list)
    for rule in rules:
        for name in rule.shape.expand():
            claims[name].append(
                Selector(name, rule.vendor, rule.source, rule.reference, rule.proof)
            )
    return {name: tuple(found) for name, found in claims.items()}


def probe_order(rules: Iterable[Rule], sweep: Iterable[str]) -> tuple[str, ...]:
    """The sweep, lowercase, with the names the rules claim moved ahead in rule order.

    Adds nothing and drops nothing: a rule name outside the sweep is not probed.
    """
    names = tuple(dict.fromkeys(s.lower() for s in sweep))
    known = frozenset(names)
    claimed = (n for n in build_dictionary(rules) if n in known)
    return tuple(dict.fromkeys((*claimed, *names)))


def rank_rules(
    rules: Iterable[Rule],
    mx_hosts: Iterable[str],
    spf_includes: Iterable[str],
) -> tuple[Rule, ...]:
    """Move rules whose hints match the domain's MX or SPF to the front.

    The sort is stable, so matched rules keep their original order, then every
    other rule in its original order. Nothing is dropped; a match only changes
    position.
    """
    mx = frozenset(_normalise(h) for h in mx_hosts)
    spf = frozenset(_normalise(d) for d in spf_includes)
    return tuple(sorted(rules, key=lambda rule: not rule.hints.matches(mx, spf)))
