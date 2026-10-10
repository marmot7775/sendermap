"""DKIM: the signing keys a domain publishes, and who holds them.

A selector name cannot be listed from DNS, only guessed, so this scans the names services are
known to use. A key reached through a CNAME into a service's zone is that service hosting it,
as strong as an SPF include. A key known only by its name is weaker: anyone can pick the name.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from ..dns import Answer
from ..model import Claim, Evidence, Finding, Gap, Kind, Observed, Severity, Unknown
from . import CANARY, Context


@dataclass(frozen=True, slots=True)
class Key:
    selector: str
    name: str
    record: str
    chain: tuple[str, ...]

    @property
    def tags(self) -> dict[str, str]:
        pairs = (part.partition("=") for part in self.record.split(";"))
        return {k.strip().lower(): v.strip() for k, sep, v in pairs if sep}

    @property
    def retired(self) -> bool:
        """An empty p= tag: the key was revoked on purpose."""
        return self.tags.get("p", "") == ""

    @property
    def algorithm(self) -> str:
        """The k= tag, lowercase; RSA when the record leaves it out (RFC 6376, section 3.6.1)."""
        return self.tags.get("k", "rsa").lower()

    @property
    def bits(self) -> int | None:
        """The key's size: for RSA, the length of the modulus read from the key itself; for
        Ed25519, 256, fixed by the type. None when the key cannot be read."""
        if self.algorithm == "ed25519":
            return 256
        if self.algorithm != "rsa":
            return None
        try:
            der = base64.b64decode("".join(self.tags.get("p", "").split()), validate=True)
        except ValueError:
            return None
        return _rsa_modulus_bits(der)

    def evidence(self, checked_at: datetime) -> Evidence:
        return Evidence(self.name, "TXT", self.described(), checked_at)

    def described(self) -> str:
        """The record with its key shortened to a prefix and its size, then where it led."""
        via = f" via {' -> '.join(self.chain)}" if self.chain else ""
        return f"{self.summary()}{via}"

    def summary(self) -> str:
        parts = []
        for part in self.record.split(";"):
            key, sep, value = part.strip().partition("=")
            if sep and key.strip().lower() == "p" and value.strip():
                size = f", {self.bits}-bit" if self.bits else ", could not read key size"
                parts.append(f"p={value.strip()[:12]}...{size}")
            elif part.strip():
                parts.append(part.strip())
        return "; ".join(parts)


async def collect(
    ctx: Context, where: str, selectors: Iterable[str], backed: Mapping[str, str]
) -> Observed:
    """Scan `selectors` under `where`. `backed` maps a selector to a service the domain's SPF
    or MX already shows, whose own selector list has that name."""
    base = f"_domainkey.{where}"
    canary = await ctx.dns.txt(f"{CANARY}.{base}")
    if canary.ok and any("p=" in r for r in canary.records):
        wildcard = Finding(
            Severity.NOTE,
            f"Every name under {base} answers with a key",
            "A wildcard record makes every selector look published, so keys there say nothing "
            "about which services sign for the domain.",
            (Evidence(f"*.{base}", "TXT", canary.records[0], ctx.checked_at),),
        )
        return Observed(findings=(wildcard,))
    names = list(dict.fromkeys(s.lower() for s in selectors))
    answers = await asyncio.gather(*(ctx.dns.txt(f"{s}.{base}") for s in names))
    claims: list[Claim] = []
    unknowns: list[Unknown] = []
    findings: list[Finding] = []
    failed: list[str] = []
    for selector, answer in zip(names, answers, strict=True):
        if not answer.answered:
            failed.append(selector)
            continue
        if answer.dangling:
            claims_, finding = _dangling(ctx, where, selector, answer)
            claims += claims_
            findings.append(finding)
            continue
        record = next((r for r in answer.records if "p=" in r), None)
        if record is None:
            continue
        key = Key(selector, answer.name, record, answer.chain)
        evidence = key.evidence(ctx.checked_at)
        service = ctx.catalog.dkim_key(selector, key.chain, backed.get(selector))
        by_cname = service is not None and ctx.catalog.dkim_cname(key.chain) == service
        if key.retired:
            if service:
                claims.append(Claim(service, Kind.DKIM_RETIRED, where, evidence))
            continue
        if service:
            kind = Kind.DKIM_CNAME if by_cname else Kind.DKIM_NAME
            claims.append(Claim(service, kind, where, evidence))
        else:
            unknowns.append(Unknown("DKIM key", selector, where))
        if key.algorithm == "rsa" and key.bits is not None and key.bits <= 1024:
            findings.append(_short_key(selector, where, key.bits, evidence))
    gaps: list[Gap] = []
    if not canary.answered:
        gaps.append(
            Gap(
                f"wildcard check: TXT at {canary.name}",
                f"{canary.status.value}, so a wildcard key was not ruled out for the selectors",
            )
        )
    if failed:
        asked = f"DKIM keys: TXT at {len(failed)} selectors under {base} ({', '.join(failed)})"
        gaps.append(Gap(asked, "lookup failed"))
    return Observed(tuple(claims), tuple(unknowns), tuple(findings), tuple(gaps))


def _short_key(selector: str, where: str, bits: int, evidence: Evidence) -> Finding:
    title = f"The {selector} key at {where} is {bits}-bit"
    if bits < 1024:
        detail = (
            "RFC 8301 (section 3.2) requires RSA signing keys of at least 1024 bits, and this one "
            "is smaller. Rotate to 2048-bit."
        )
        return Finding(Severity.RISK, title, detail, (evidence,))
    detail = "Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit."
    return Finding(Severity.WARNING, title, detail, (evidence,))


# DER tags in an RSA public key.
_SEQUENCE, _INTEGER, _BIT_STRING = 0x30, 0x02, 0x03


def _rsa_modulus_bits(der: bytes) -> int | None:
    """The bit length of the RSA modulus in a SubjectPublicKeyInfo, the form RFC 6376 asks for,
    or in a bare RSAPublicKey, which some senders publish instead. None when it does not parse."""
    try:
        tag, body, rest = _tlv(der)
        if tag != _SEQUENCE or rest:
            return None
        tag, value, after = _tlv(body)
        if tag == _SEQUENCE:  # SubjectPublicKeyInfo: the algorithm, then the key in a BIT STRING
            tag, wrapped, extra = _tlv(after)
            if tag != _BIT_STRING or extra or wrapped[:1] != b"\x00":
                return None
            tag, body, rest = _tlv(wrapped[1:])
            if tag != _SEQUENCE or rest:
                return None
            tag, value, after = _tlv(body)
        exponent_tag, _, tail = _tlv(after)
    except ValueError:
        return None
    if tag != _INTEGER or exponent_tag != _INTEGER or tail:
        return None
    return int.from_bytes(value).bit_length() or None


def _tlv(data: bytes) -> tuple[int, bytes, bytes]:
    """One DER element: its tag, its value, and the bytes after it. ValueError if cut short."""
    if len(data) < 2:
        raise ValueError("truncated")
    tag, length, start = data[0], data[1], 2
    if length & 0x80:
        size = length & 0x7F
        if not 0 < size <= 4 or len(data) < 2 + size:
            raise ValueError("bad length")
        length, start = int.from_bytes(data[2 : 2 + size]), 2 + size
    if start + length > len(data):
        raise ValueError("truncated")
    return tag, data[start : start + length], data[start + length :]


def _dangling(
    ctx: Context, where: str, selector: str, answer: Answer
) -> tuple[list[Claim], Finding]:
    target = answer.target or ""
    evidence = Evidence(answer.name, "CNAME", " -> ".join(answer.chain), ctx.checked_at)
    service = ctx.catalog.dkim_cname(answer.chain)
    claims = [Claim(service, Kind.DKIM_DANGLING, where, evidence)] if service else []
    finding = Finding(
        Severity.RISK,
        f"The {selector} DKIM record points at a name that does not exist",
        f"{answer.name} is an alias for {target}, which has no record. If whoever controls that "
        "name publishes a key there, mail they sign passes DKIM as this domain. Remove the alias "
        "if the service is no longer used.",
        (evidence,),
    )
    return claims, finding
