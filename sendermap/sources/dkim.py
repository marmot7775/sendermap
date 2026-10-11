"""DKIM: the signing keys a domain publishes, and who holds them.

A selector name cannot be listed from DNS, only guessed, so this scans the names services are
known to use. A key reached through a CNAME into a service's zone is that service hosting it,
as strong as an SPF include. A key known only by its name is weaker: anyone can pick the name.

Two names are asked first: a name nobody publishes under _domainkey, and _domainkey itself.
When the zone answers no such name for the first, it denies names classically, and then no such
name at _domainkey means no selector exists under it (RFC 8020 section 2, RFC 4592 section
2.2.3), while an empty answer there means at least one does. A zone that answers empty for names
that do not exist (compact denial, RFC 9824) says nothing about existence by its answer code, so
the sweep runs as it would anyway.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from ..dns import Answer, Status
from ..model import (
    Absence,
    Checked,
    Claim,
    Denial,
    Evidence,
    Finding,
    Gap,
    Kind,
    Observed,
    Severity,
    Unknown,
)
from . import CANARY, Context, negative

# When _domainkey says no selector exists, the ranked names asked anyway, besides the backed ones,
# as a check on servers that answer no such name for a name with names below it (RFC 8020 s. 5).
CHECK_PROBES = 8
NO_SELECTORS = "no selectors exist"


@dataclass(frozen=True, slots=True)
class Key:
    selector: str
    name: str
    record: str
    chain: tuple[str, ...]

    @property
    def tags(self) -> dict[str, str]:
        return tags(self.record)

    @property
    def revoked(self) -> bool:
        """An empty p= tag: the key was revoked on purpose (RFC 6376, section 3.6.1)."""
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


def tags(record: str) -> dict[str, str]:
    """A DKIM record's tags by exact name, so ap= or rp= is never read as p=."""
    pairs = (part.partition("=") for part in record.split(";"))
    return {k.strip().lower(): v.strip() for k, sep, v in pairs if sep}


async def collect(
    ctx: Context, where: str, selectors: Iterable[str], backed: Mapping[str, Claim]
) -> Observed:
    """Scan `selectors` under `where`. `backed` maps a selector to the SPF or MX claim of a
    service the domain already shows, whose own selector list has that name."""
    base = f"_domainkey.{where}"
    canary, node = await asyncio.gather(ctx.dns.txt(f"{CANARY}.{base}"), ctx.dns.txt(base))
    denial = _denial(canary)
    if canary.ok and any("p" in tags(r) for r in canary.records):
        wildcard = Finding(
            Severity.NOTE,
            f"Every name under {base} answers with a key",
            "A wildcard record makes every selector look published, so keys there say nothing "
            "about which services sign for the domain.",
            (Evidence(f"*.{base}", "TXT", canary.records[0], ctx.checked_at),),
        )
        return Observed(findings=(wildcard,), checked=(Checked(where, denial=denial),))
    names = list(dict.fromkeys(s.lower() for s in selectors))
    classic = denial is Denial.CLASSIC
    contradicted = Observed()
    if classic and node.status is Status.NXDOMAIN and not node.chain:
        check = list(dict.fromkeys([*names[:CHECK_PROBES], *(s.lower() for s in backed)]))
        answers = await _ask(ctx, base, check)
        found = next((a for a in answers if _exists(a)), None)
        if found is None:
            happened = (
                f"{NO_SELECTORS}: {base} does not exist and the zone returns no such name for "
                f"names that do not exist. The sweep of {len(names)} names was not run for that "
                f"reason; only the {len(check)} names the domain's MX and SPF back or hint at were "
                "asked, as a check on servers that answer no such name for a name with names "
                "below it (RFC 8020 section 5)"
            )
            evidence = (negative(node, ctx.checked_at), negative(canary, ctx.checked_at))
            absence = Absence(f"DKIM keys at {where}", happened, evidence)
            return _scan(
                ctx, where, check, answers, backed=backed, canary=canary, denial=denial
            ) + Observed(absences=(absence,))
        what = "a key" if any("p" in tags(r) for r in found.records) else "a record"
        happened = (
            f"the server answered no such name at {base} but {what} exists at {found.name}, so "
            "existence could not be read from it"
        )
        contradicted = Observed(gaps=(Gap(f"DKIM keys at {where}", happened),))
    answers = await _ask(ctx, base, names)
    observed = (
        _scan(ctx, where, names, answers, backed=backed, canary=canary, denial=denial)
        + contradicted
    )
    if (
        classic
        and node.status is Status.NOANSWER
        and all(a.status is Status.NXDOMAIN and not a.chain for a in answers)
    ):
        happened = f"selectors exist but none of the {len(names)} names asked is one"
        absence = Absence(f"DKIM keys at {where}", happened, (negative(node, ctx.checked_at),))
        observed += Observed(absences=(absence,))
    return observed


def _denial(canary: Answer) -> Denial:
    """How the zone answers for a name that does not exist, read from the wildcard check."""
    if canary.ok:
        return Denial.WILDCARD
    if canary.status is Status.NXDOMAIN:
        return Denial.CLASSIC
    if canary.status is Status.NOANSWER:
        return Denial.NONE_BY_RCODE
    return Denial.UNKNOWN


def _exists(answer: Answer) -> bool:
    """Whether an answer shows its name exists: records, an empty answer, or a CNAME there."""
    return answer.ok or answer.status is Status.NOANSWER or bool(answer.chain)


async def _ask(ctx: Context, base: str, names: list[str]) -> list[Answer]:
    return list(await asyncio.gather(*(ctx.dns.txt(f"{s}.{base}") for s in names)))


def _scan(
    ctx: Context,
    where: str,
    names: list[str],
    answers: list[Answer],
    *,
    backed: Mapping[str, Claim],
    canary: Answer,
    denial: Denial,
) -> Observed:
    """What the answers for `names` show, with a gap for each that failed."""
    echo = frozenset(canary.records) if canary.ok else None
    observed = Observed()
    failed: list[str] = []
    for selector, answer in zip(names, answers, strict=True):
        if answer.answered:
            observed += _read(ctx, where, selector, answer, backed=backed.get(selector), echo=echo)
        else:
            failed.append(selector)
    gaps: list[Gap] = []
    if not canary.answered:
        gaps.append(
            Gap(
                f"wildcard check: TXT at {canary.name}",
                f"{canary.status.value}, so a wildcard key was not ruled out for the selectors",
            )
        )
    if failed:
        base = f"_domainkey.{where}"
        asked = f"DKIM keys: TXT at {len(failed)} selectors under {base} ({', '.join(failed)})"
        gaps.append(Gap(asked, "lookup failed"))
    checked = Checked(where, tuple(names), denial=denial)
    return observed + Observed(gaps=tuple(gaps), checked=(checked,))


def _read(
    ctx: Context,
    where: str,
    selector: str,
    answer: Answer,
    *,
    backed: Claim | None,
    echo: frozenset[str] | None,
) -> Observed:
    """What one selector's answer shows. `echo` is what a wildcard answers, if anything. A key
    credited through `backed` carries that claim's record as well as its own."""
    if answer.dangling:
        claims, finding = _dangling(ctx, where, selector, answer)
        return Observed(tuple(claims), findings=(finding,))
    if not answer.records or frozenset(answer.records) == echo:
        return Observed()  # nothing here, or a wildcard's answer that is not a key
    record = next((r for r in answer.records if "p" in tags(r)), None)
    if record is None:
        return Observed(findings=(_malformed(ctx, where, selector, answer),))
    key = Key(selector, answer.name, record, answer.chain)
    evidence = key.evidence(ctx.checked_at)
    service = ctx.catalog.dkim_key(selector, key.chain, backed.service if backed else None)
    by_cname = service is not None and ctx.catalog.dkim_cname(key.chain) == service
    via = (backed.evidence,) if backed and not by_cname and service == backed.service else ()
    if key.revoked:
        claim = Claim(service, Kind.DKIM_REVOKED, where, evidence, via) if service else None
        return Observed((claim,) if claim else ())
    if service:
        kind = Kind.DKIM_CNAME if by_cname else Kind.DKIM_NAME
        found = Observed(claims=(Claim(service, kind, where, evidence, via),))
    else:
        # A key behind a CNAME no service's pattern matches is listed with where it is served.
        value = f"{selector} via {' -> '.join(key.chain)}" if key.chain else selector
        found = Observed(unknowns=(Unknown("DKIM key", value, where, evidence),))
    if key.algorithm == "rsa" and key.bits is not None and key.bits <= 1024:
        found += Observed(findings=(_short_key(selector, where, key.bits, evidence),))
    return found


def _malformed(ctx: Context, where: str, selector: str, answer: Answer) -> Finding:
    evidence = tuple(Evidence(answer.name, "TXT", r, ctx.checked_at) for r in answer.records)
    return Finding(
        Severity.WARNING,
        f"The {selector} DKIM record at {where} has no p= tag",
        "RFC 6376 (section 3.6.1) requires p=. Without it the record is malformed, not a key, so "
        "mail signed with this selector fails DKIM. A revoked key is different: it keeps p= and "
        "leaves it empty.",
        evidence,
    )


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
