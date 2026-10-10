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
class Rule:
    """What a vendor names its selectors, and how we know."""

    vendor: str
    shape: Shape
    source: Source
    reference: str = ""

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
    return Rule(
        vendor=raw["vendor"],
        shape=shape,
        source=Source(raw["source"]),
        reference=raw.get("reference", ""),
    )


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
