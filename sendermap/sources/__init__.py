"""One module per kind of public evidence. Each turns what it observes into claims."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..catalog import Catalog
from ..dns import Lookups


@dataclass(frozen=True, slots=True)
class Context:
    domain: str
    dns: Lookups
    catalog: Catalog
    http: httpx.AsyncClient | None = None
