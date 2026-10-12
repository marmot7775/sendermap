"""Sendermap: which services send email as a domain, and the public evidence for each."""

import json
from importlib import metadata, resources
from typing import Any

from .engine import map_domain
from .model import Finding, SenderMap, Service, Severity, Tier

__all__ = ["Finding", "SenderMap", "Service", "Severity", "Tier", "map_domain", "schema"]
SCHEMA_FILE = "data/schema/sendermap-1.json"


def schema() -> dict[str, Any]:
    """The JSON Schema of SenderMap.to_dict() under sendermap/1, which grows by addition only."""
    loaded: dict[str, Any] = json.loads(resources.files(__name__).joinpath(SCHEMA_FILE).read_text())
    return loaded


try:
    __version__ = metadata.version(__name__)  # set at build time from the git tag
except metadata.PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0"
