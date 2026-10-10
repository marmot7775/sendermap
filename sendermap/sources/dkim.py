"""DKIM: the signing keys a domain publishes, and who holds them.

A selector name cannot be listed from DNS, only guessed, so this scans the names services are
known to use. A key reached through a CNAME into a service's zone is that service hosting it,
as strong as an SPF include. A key known only by its name is weaker: anyone can pick the name.
"""

from __future__ import annotations

import asyncio
import base64
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ..dns import Answer
from ..model import Claim, Evidence, Finding, Gap, Kind, Observed, Severity, Unknown
from . import Context


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
    def bits(self) -> int | None:
        """RSA modulus size, from the length of the public key. None for Ed25519 or unreadable."""
        if self.tags.get("k", "rsa").lower() != "rsa":
            return None
        try:
            der = base64.b64decode(self.tags.get("p", "").replace(" ", ""), validate=False)
        except ValueError:
            return None
        # A SubjectPublicKeyInfo wraps the modulus in about 38 bytes of structure.
        for size, limit in ((1024, 200), (2048, 330), (3072, 460), (4096, 600)):
            if len(der) <= limit:
                return size
        return None

    def evidence(self) -> Evidence:
        via = f" via {' -> '.join(self.chain)}" if self.chain else ""
        return Evidence(self.name, "TXT", f"{_short(self.record)}{via}")


def _short(record: str, width: int = 72) -> str:
    return record if len(record) <= width else record[: width - 3] + "..."


async def collect(
    ctx: Context, where: str, selectors: Iterable[str], backed: Mapping[str, str]
) -> Observed:
    """Scan `selectors` under `where`. `backed` maps a selector to a service the domain's SPF
    or MX already shows, whose own selector list has that name."""
    base = f"_domainkey.{where}"
    canary = await ctx.dns.txt(f"sm{secrets.token_hex(5)}.{base}")
    if canary.ok and any("p=" in r for r in canary.records):
        wildcard = Finding(
            Severity.NOTE,
            f"Every name under {base} answers with a key",
            "A wildcard record makes every selector look published, so keys there say nothing "
            "about which services sign for the domain.",
            (Evidence(canary.name, "TXT", canary.records[0]),),
        )
        return Observed(findings=(wildcard,))
    names = list(dict.fromkeys(s.lower() for s in selectors))
    answers = await asyncio.gather(*(ctx.dns.txt(f"{s}.{base}") for s in names))
    claims: list[Claim] = []
    unknowns: list[Unknown] = []
    findings: list[Finding] = []
    failed = 0
    for selector, answer in zip(names, answers, strict=True):
        if not answer.answered:
            failed += 1
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
        service = ctx.catalog.dkim_key(selector, key.chain, backed.get(selector))
        by_cname = service is not None and ctx.catalog.dkim_cname(key.chain) == service
        if key.retired:
            if service:
                claims.append(Claim(service, Kind.DKIM_RETIRED, where, key.evidence()))
            continue
        if service:
            claims.append(
                Claim(
                    service, Kind.DKIM_CNAME if by_cname else Kind.DKIM_NAME, where, key.evidence()
                )
            )
        else:
            unknowns.append(Unknown("DKIM key", selector, where))
        if key.bits == 1024:
            findings.append(
                Finding(
                    Severity.WARNING,
                    f"The {selector} key at {where} is 1024-bit",
                    "Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit.",
                    (key.evidence(),),
                )
            )
    gaps = (Gap(f"{failed} DKIM selectors at {where}", "lookups failed"),) if failed else ()
    return Observed(tuple(claims), tuple(unknowns), tuple(findings), gaps)


def _dangling(
    ctx: Context, where: str, selector: str, answer: Answer
) -> tuple[list[Claim], Finding]:
    target = answer.target or ""
    evidence = Evidence(answer.name, "CNAME", " -> ".join(answer.chain))
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
