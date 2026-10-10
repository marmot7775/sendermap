"""Selector dictionary for Sendermap.

A DKIM selector cannot be listed from DNS, so Sendermap probes a
dictionary of candidates. Every candidate carries its provenance:
the vendor it points to and how that knowledge was obtained. Rules
are data, loaded from a YAML file, so the dictionary can be reviewed
and contributed to without touching Python.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import date
from enum import Enum
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Any, Protocol

import yaml


class Source(Enum):
    VENDOR_DOCS = "vendor_docs"
    AGGREGATE_REPORT = "aggregate_report"
    PATTERN = "pattern"


class Shape(Protocol):
    """Anything that expands into selector names for a given date."""

    def expand(self, today: date) -> Iterator[str]: ...


@dataclass(frozen=True, slots=True)
class Fixed:
    """An explicit set of names."""

    names: tuple[str, ...]

    def expand(self, today: date) -> Iterator[str]:
        return iter(self.names)


@dataclass(frozen=True, slots=True)
class Numbered:
    """A prefix followed by 1 through stop: selector1, selector2."""

    prefix: str
    stop: int

    def expand(self, today: date) -> Iterator[str]:
        return (f"{self.prefix}{n}" for n in range(1, self.stop + 1))


@dataclass(frozen=True, slots=True)
class Dated:
    """A prefix followed by year and month: ses202610."""

    prefix: str
    years_back: int

    def expand(self, today: date) -> Iterator[str]:
        first_year = today.year - self.years_back
        for year in range(first_year, today.year + 1):
            for month in range(1, 13):
                yield f"{self.prefix}{year}{month:02d}"


SHAPES: Mapping[str, type] = {
    "fixed": Fixed,
    "numbered": Numbered,
    "dated": Dated,
}


@dataclass(frozen=True, slots=True)
class Hints:
    """What a vendor's customers publish elsewhere in DNS.

    mx holds hostname suffixes found in the vendor's MX records; spf holds
    include domains the vendor tells customers to add. Both are lowercase.
    """

    mx: tuple[str, ...] = ()
    spf: tuple[str, ...] = ()

    def matches(self, mx_hosts: frozenset[str], spf_includes: frozenset[str]) -> bool:
        """True when any MX host ends in a hint suffix or any include is a hint domain.

        Both arguments must already be lowercase with no trailing dot. A suffix
        matches on a label boundary, so google.com matches aspmx.l.google.com
        but not notgoogle.com.
        """
        for host in mx_hosts:
            for suffix in self.mx:
                if host == suffix or host.endswith("." + suffix):
                    return True
        return not spf_includes.isdisjoint(self.spf)


@dataclass(frozen=True, slots=True)
class Rule:
    """What a vendor names its selectors, and how we know."""

    vendor: str
    shape: Shape
    source: Source
    reference: str = ""
    hints: Hints = Hints()

    def __post_init__(self) -> None:
        if self.source is Source.VENDOR_DOCS and not self.reference:
            raise ValueError(f"{self.vendor}: vendor docs claimed, no reference given")


@dataclass(frozen=True, slots=True)
class Selector:
    """One probe candidate with its provenance attached."""

    name: str
    vendor: str
    source: Source
    reference: str


def parse_rule(raw: Mapping[str, Any]) -> Rule:
    """Build a Rule from one mapping in the rules file."""
    shape_spec = dict(raw["shape"])
    kind = shape_spec.pop("kind")
    if kind == "fixed":
        shape_spec["names"] = tuple(shape_spec["names"])
    shape = SHAPES[kind](**shape_spec)
    hint_spec = raw.get("hints") or {}
    hints = Hints(**{key: tuple(map(_normalise, names)) for key, names in hint_spec.items()})
    return Rule(
        vendor=raw["vendor"],
        shape=shape,
        source=Source(raw["source"]),
        reference=raw.get("reference", ""),
        hints=hints,
    )


def _normalise(name: str) -> str:
    """Lowercase a DNS name and drop any trailing dot."""
    return name.lower().rstrip(".")


# Found by package path, not the working directory, so the rules load the same from an
# installed wheel as from a checkout.
RULES_FILE = resources.files("sendermap").joinpath("data/selectors.yaml")


def load_rules(path: Traversable = RULES_FILE) -> tuple[Rule, ...]:
    """Read every rule from a YAML file; the rules shipped with Sendermap by default."""
    with path.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or []
    return tuple(parse_rule(raw) for raw in document)


def build_dictionary(
    rules: Iterable[Rule],
    today: date | None = None,
) -> dict[str, tuple[Selector, ...]]:
    """Expand rules into candidates keyed by name.

    A name claimed by several vendors keeps every claim. A collision
    is a fact about the world; the caller decides what to do with it.
    """
    today = today or date.today()
    claims: defaultdict[str, list[Selector]] = defaultdict(list)
    for rule in rules:
        for name in rule.shape.expand(today):
            claims[name].append(Selector(name, rule.vendor, rule.source, rule.reference))
    return {name: tuple(found) for name, found in claims.items()}


def rank_rules(
    rules: Iterable[Rule],
    mx_hosts: Iterable[str],
    spf_includes: Iterable[str],
) -> tuple[Rule, ...]:
    """Move rules whose hints match the domain's MX or SPF to the front.

    Matched rules keep their original order, then every other rule in its
    original order. Nothing is dropped; a match only changes position.
    """
    mx = frozenset(_normalise(h) for h in mx_hosts)
    spf = frozenset(_normalise(d) for d in spf_includes)
    matched: list[Rule] = []
    rest: list[Rule] = []
    for rule in rules:
        (matched if rule.hints.matches(mx, spf) else rest).append(rule)
    return (*matched, *rest)
