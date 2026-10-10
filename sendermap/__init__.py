"""Sendermap: which services send email as a domain, and the public evidence for each."""

from .engine import map_domain
from .model import Finding, SenderMap, Service, Severity, Tier

__all__ = ["Finding", "SenderMap", "Service", "Severity", "Tier", "map_domain"]
__version__ = "0.1.0.dev0"
