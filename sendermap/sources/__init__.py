"""One module per kind of public evidence. Each turns what it observes into claims."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import httpx

from ..catalog import Catalog
from ..dns import Lookups

# Asked before a wave of probes: a name nobody publishes, so an answer here is a wildcard. Fixed,
# not random, so the same DNS answers give the same map.
CANARY = "sendermap-wildcard-check"


@dataclass(frozen=True, slots=True)
class Context:
    domain: str
    dns: Lookups
    catalog: Catalog
    checked_at: datetime  # every Evidence a source records is dated by it
    http: httpx.AsyncClient | None = None


def http_failure(error: httpx.HTTPError) -> str:
    """What happened to a web request, in a few words: its status, or the kind of failure."""
    if isinstance(error, httpx.HTTPStatusError):
        return f"HTTP {error.response.status_code}"
    return f"failed: {type(error).__name__}"
