"""Proofs: where a vendor fact was seen live, and the checks every proof must pass on loading.

A proof names a domain, the record that showed the fact (a DNS name, or the URL of a page), and
the day it was checked. Each kind of pattern says where its record may sit, so a proof cannot
point somewhere that could not show the pattern.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class Proof:
    """A live domain seen publishing a pattern.

    record is the name or page as found, such as k2._domainkey.example.com or
    https://example.com/; date is the day it was checked, as YYYY-MM-DD.
    """

    domain: str
    record: str
    date: str


def parse(raw: Mapping[str, Any]) -> Proof:
    """A field left out arrives blank, so check() names it as missing."""
    return Proof(*(str(raw.get(field) or "") for field in ("domain", "record", "date")))


def check(where: str, proof: Proof) -> None:
    """Reject a proof with a blank field or a malformed date."""
    for field in ("domain", "record", "date"):
        if missing(getattr(proof, field)):
            raise ValueError(f"{where}: proof has no {field}")
    try:
        date.fromisoformat(proof.date)
    except ValueError:
        raise ValueError(f"{where}: proof date {proof.date!r} is not YYYY-MM-DD") from None


def check_record(where: str, field: str, proof: Proof) -> None:
    """Reject a record that could not show a pattern of this kind on the proof's domain."""
    domain, record = normalise(proof.domain), proof.record.strip()
    name = normalise(record)
    if field in PAGE_FIELDS:
        host = urlsplit(record).hostname or ""
        ok = record.startswith("https://") and _at_or_under(host, domain)
        rule = "an https URL on the domain"
    elif field == "reporting":
        ok = name in (f"_dmarc.{domain}", f"_smtp._tls.{domain}")
        rule = f"_dmarc.{domain} or _smtp._tls.{domain}"
    elif field == "verification_txt":
        ok = name == domain
        rule = "the domain itself"
    elif field == "delegation_ns":
        ok = name.endswith(f".{domain}")
        rule = f"a name under {domain}"
    elif field == "dkim_cname":
        ok = name.endswith(f"._domainkey.{domain}")
        rule = f"a name under _domainkey.{domain}"
    else:
        ok = _at_or_under(name, domain)
        rule = "the domain or a name under it"
    if not ok:
        raise ValueError(f"{where}: proof record {record!r} is not {rule}")


# Patterns whose proof is a page: the record is its URL. A setup's page is the vendor's own
# documentation, so its domain is the vendor's.
PAGE_FIELDS = frozenset({"website", "subprocessor_names", "setup"})


def normalise(name: str) -> str:
    """Lowercase a DNS name and drop any trailing dot."""
    return name.lower().rstrip(".")


def missing(text: str | None) -> bool:
    """True for None, an empty string, or only whitespace."""
    return text is None or not text.strip()


def _at_or_under(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)
