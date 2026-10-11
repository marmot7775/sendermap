"""The services a client says they use, against what the map found.

Pure: it reads a finished map, the names the client wrote and the catalog, and asks nothing. A
claimed name matches a service only by its name or one of its aliases, exactly, after both are
normalised (`catalog.normalise`); nothing fuzzier. A name that matches no service is kept as the
client wrote it, so their words are never silently dropped.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import replace

from .catalog import Catalog
from .model import Reconciled, Reconciliation, Role, SenderMap


def reconcile(result: SenderMap, claimed: Iterable[str], catalog: Catalog) -> Reconciliation:
    """Four parts: the claimed services the map found, each with its tier; every sending service
    found that nobody claimed (a service that only receives reports is not unclaimed); the
    claimed services with no claim at any name checked; and the claimed names no service goes
    by. Found services keep the map's order; the rest keep the order they were claimed in."""
    wrote: dict[str, list[str]] = {}
    unknown: list[str] = []
    for text in names(claimed):
        if service := catalog.named(text):
            wrote.setdefault(service, []).append(text)
        else:
            unknown.append(text)
    found = {s.name for s in result.services}
    return Reconciliation(
        confirmed=tuple(
            Reconciled(s.name, s.tier, tuple(wrote[s.name]))
            for s in result.services
            if s.name in wrote
        ),
        unclaimed=tuple(
            Reconciled(s.name, s.tier)
            for s in result.services
            if s.role is Role.SENDER and s.name not in wrote
        ),
        unfound=tuple(
            Reconciled(service, None, tuple(texts))
            for service, texts in wrote.items()
            if service not in found
        ),
        unknown=tuple(unknown),
    )


def with_claimed(result: SenderMap, claimed: Sequence[str], catalog: Catalog) -> SenderMap:
    """The map with its reconciliation, or the map as it is when nothing was claimed."""
    if not names(claimed):
        return result
    return replace(result, reconciliation=reconcile(result, claimed, catalog))


def names(claimed: Iterable[str]) -> list[str]:
    """The claimed names as written, trimmed, blanks left out, each once."""
    return list(dict.fromkeys(text.strip() for text in claimed if text.strip()))


def split(text: str) -> list[str]:
    """A comma separated list of names, as the command line and the API take it."""
    return names(text.split(","))
