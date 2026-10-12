"""check_host() from RFC 7208: what a receiver decides for one address, domain and sender.

The walk in `spf.py` reads the tree to find out who a domain names. This module asks the other
question, the one a receiver asks: does this record authorize this address? It follows RFC 7208
section 4 to the letter, with the limits of section 4.6.4, the mechanisms of section 5, the
modifiers of section 6 and the macros of section 7, and is held to the RFC 7208 test suite
(`tests/test_spf_eval.py`).

DNS is read only through `ctx.dns`, so every answer is cached, counted and replayable. Nothing
here raises for a failed lookup: it is temperror, and the reason names the question.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from urllib.parse import quote

from ..dns import Answer, Status, norm
from ..model import Evidence
from . import Context

LOOKUP_LIMIT = 10  # section 4.6.4: terms that cause DNS queries
VOID_LIMIT = 2  # section 4.6.4: lookups that answer no such name or no records
MX_LIMIT = 10  # section 4.6.4: MX records one mx mechanism may look at
PTR_LIMIT = 10  # section 4.6.4: PTR names one ptr mechanism, or the p macro, may look at

type Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class Result(StrEnum):
    """Section 2.6."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"


_QUALIFIER = {"+": Result.PASS, "-": Result.FAIL, "~": Result.SOFTFAIL, "?": Result.NEUTRAL}


@dataclass(frozen=True, slots=True)
class Verdict:
    """What check_host() decided, and what decided it.

    `mechanism` is the term that matched, as written, and `record` the SPF record it sits in.
    For a match inside an include it is the term inside the included record, so a pass through
    `include:sendgrid.net` names the range in SendGrid's record that held the address; the
    result is still the one the outer include's qualifier gives. With no match, `mechanism` is
    None and `record` is the record whose default applied. `path` holds the include and
    redirect links walked from the domain to `record`, outermost first, each as the SPF record
    found at the link's target. `lookups` counts the terms that caused DNS queries (section
    4.6.4), and `reason` says, for an error, what went wrong, naming the question for a
    temperror."""

    result: Result
    mechanism: str | None = None
    record: Evidence | None = None
    path: tuple[Evidence, ...] = ()
    lookups: int = 0
    void_lookups: int = 0
    reason: str = ""


class _Error(Exception):
    """A permerror or temperror: it ends the whole check, from however deep it was found."""

    def __init__(self, result: Result, reason: str) -> None:
        super().__init__(reason)
        self.result = result
        self.reason = reason


def _perm(reason: str) -> _Error:
    return _Error(Result.PERMERROR, reason)


def _temp(answer: Answer) -> _Error:
    return _Error(Result.TEMPERROR, f"lookup failed: {answer.name} {answer.rtype}")


def mail_from(mailfrom: str, helo: str) -> tuple[str, str]:
    """The sender and the domain to check for an SMTP MAIL FROM (sections 2.4 and 4.3): an
    empty MAIL FROM checks postmaster at the HELO name, and a missing local part is
    postmaster."""
    if not mailfrom:
        return f"postmaster@{helo}", helo
    local, at, domain = mailfrom.rpartition("@")
    if not at:
        return f"postmaster@{mailfrom}", mailfrom
    return f"{local or 'postmaster'}@{domain}", domain


async def check_host(ctx: Context, ip: str, domain: str, sender: str, helo: str) -> Verdict:
    """Section 4: the result for `ip` sending as `sender`, checked against `domain`'s record."""
    try:
        address = _address(ip)
    except ValueError:
        return Verdict(Result.PERMERROR, reason=f"not an IP address: {ip}")
    if not _valid_name(domain):
        return Verdict(Result.NONE, reason=f"not a domain name: {domain}")
    local, _, sender_domain = sender.rpartition("@")
    check = _Check(ctx, address, local or "postmaster", sender_domain or domain, helo)
    try:
        record = await check.record(domain)
        if record is None:
            return Verdict(Result.NONE, reason=f"no SPF record at {norm(domain)}")
        outcome = await check.evaluate(domain, record)
    except _Error as error:
        outcome = Verdict(error.result, reason=error.reason)
    return replace(outcome, lookups=check.lookups, void_lookups=check.voids)


def _address(ip: str) -> Address:
    address = ipaddress.ip_address(ip.strip())
    # Section 5: an IPv4-mapped IPv6 address is checked as the IPv4 address it carries.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


# ---------------------------------------------------------------- parsing (section 4.6, 12)

_MODIFIER = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)=(.*)", re.S)
_MECHANISM = re.compile(r"([+\-~?]?)([A-Za-z0-9]*)(.*)", re.S)
_IP4 = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
_CIDR4 = r"(?:/(0|[1-9]\d?))"
_CIDR6 = r"(?:/(0|[1-9]\d{0,2}))"
_DUAL_CIDR = re.compile(rf"(.*?){_CIDR4}?(?:/{_CIDR6})?", re.S)
_TOPLABEL = re.compile(r"[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*|[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9]")
_MACRO = re.compile(r"%\{([A-Za-z])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-", re.I)
_DOMAIN_LETTERS = frozenset("slodiphv")  # c, r and t are for exp text alone (section 7.1)


@dataclass(frozen=True, slots=True)
class _Term:
    text: str
    qualifier: Result
    name: str  # the mechanism, lowercase
    domain: str | None = None  # the domain-spec, unexpanded
    cidr4: int = 32
    cidr6: int = 128
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    @property
    def counts(self) -> bool:
        return self.name in ("include", "a", "mx", "ptr", "exists")


@dataclass(frozen=True, slots=True)
class _Record:
    evidence: Evidence
    terms: tuple[_Term, ...]
    redirect: str | None = None
    has_all: bool = False


def _parse(evidence: Evidence) -> _Record:
    """The whole record, checked before any of it is evaluated: a syntax error anywhere is a
    permerror (section 4.6)."""
    text = evidence.value
    if not text.isascii() or not text.isprintable():
        raise _perm(f"not 7-bit printable text in {evidence.name}'s record")
    terms: list[_Term] = []
    modifiers: dict[str, str] = {}
    for word in text.split(" ")[1:]:
        if not word:
            continue
        modifier = _MODIFIER.fullmatch(word)
        if modifier:
            name, value = modifier[1].lower(), modifier[2]
            if name in modifiers and name in ("redirect", "exp"):
                raise _perm(f"{name} given twice in {evidence.name}'s record")
            if name in ("redirect", "exp"):
                _domain_spec(value, word)
            else:
                _tokens(value, word)  # an unknown modifier is ignored, but must parse
            modifiers[name] = value
            continue
        terms.append(_term(word))
    has_all = any(t.name == "all" for t in terms)
    return _Record(evidence, tuple(terms), modifiers.get("redirect"), has_all)


def _term(word: str) -> _Term:
    match = _MECHANISM.fullmatch(word)
    assert match  # every group can be empty
    name, rest = match[2].lower(), match[3]
    parse = _MECHANISMS.get(name)
    if parse is None:
        raise _perm(f"unknown mechanism: {word}")
    return parse(_Term(word, _QUALIFIER.get(match[1], Result.PASS), name), rest)


def _all(term: _Term, rest: str) -> _Term:
    if rest:
        raise _perm(f"all takes nothing: {term.text}")
    return term


def _named(term: _Term, rest: str) -> _Term:
    """include and exists: a domain, nothing else."""
    if not rest.startswith(":"):
        raise _perm(f"{term.name} needs a domain: {term.text}")
    return replace(term, domain=_domain_spec(rest[1:], term.text))


def _with_cidr(term: _Term, rest: str) -> _Term:
    """a and mx: an optional domain, then optional prefix lengths."""
    spec, cidr4, cidr6 = _split_cidr(rest, term.text)
    if spec is not None and not spec.startswith(":"):
        raise _perm(f"unreadable term: {term.text}")
    domain = _domain_spec(spec[1:], term.text) if spec is not None else None
    return replace(term, domain=domain, cidr4=cidr4, cidr6=cidr6)


def _ptr(term: _Term, rest: str) -> _Term:
    if rest and not rest.startswith(":"):
        raise _perm(f"ptr takes no prefix length: {term.text}")
    return replace(term, domain=_domain_spec(rest[1:], term.text) if rest else None)


def _ip4(term: _Term, rest: str) -> _Term:
    net = re.fullmatch(rf":({_IP4}){_CIDR4}?", rest)
    if not net or int(net[2] or 32) > 32:
        raise _perm(f"not an IPv4 network: {term.text}")
    return replace(term, network=ipaddress.IPv4Network(f"{net[1]}/{net[2] or 32}", False))


def _ip6(term: _Term, rest: str) -> _Term:
    net = re.fullmatch(rf":([0-9A-Fa-f:.]+){_CIDR6}?", rest)
    try:
        if not net or ":" not in net[1] or int(net[2] or 128) > 128:
            raise ValueError
        network = ipaddress.IPv6Network(f"{net[1]}/{net[2] or 128}", strict=False)
    except ValueError:
        raise _perm(f"not an IPv6 network: {term.text}") from None
    return replace(term, network=network)


_MECHANISMS: dict[str, Callable[[_Term, str], _Term]] = {
    "all": _all,
    "include": _named,
    "exists": _named,
    "a": _with_cidr,
    "mx": _with_cidr,
    "ptr": _ptr,
    "ip4": _ip4,
    "ip6": _ip6,
}


def _split_cidr(rest: str, word: str) -> tuple[str | None, int, int]:
    """Split `:domain/24//64` into its parts (dual-cidr-length, section 5.6). The domain may
    itself hold a "/", so the lengths are read from the end."""
    match = _DUAL_CIDR.fullmatch(rest)
    assert match  # the first group takes anything
    spec, cidr4, cidr6 = match[1], match[2], match[3]
    if int(cidr4 or 0) > 32 or int(cidr6 or 0) > 128:
        raise _perm(f"prefix length out of range: {word}")
    return (spec or None), int(cidr4 or 32), int(cidr6 or 128)


def _tokens(spec: str, word: str) -> list[str]:
    """A macro-string as literal text and macro-expands (section 7.1), or a permerror."""
    tokens: list[str] = []
    at = 0
    while at < len(spec):
        if spec[at] != "%":
            end = spec.find("%", at)
            end = len(spec) if end < 0 else end
            literal = spec[at:end]
            if not all("\x21" <= ch <= "\x7e" for ch in literal):
                raise _perm(f"not a visible character in {word!r}")
            tokens.append(literal)
            at = end
            continue
        macro = _MACRO.match(spec, at)
        if not macro or (macro[1] and macro[1].lower() not in "slodiphvcrt"):
            raise _perm(f"bad macro in {word}")
        tokens.append(macro[0])
        at = macro.end()
    return tokens


def _domain_spec(spec: str, word: str) -> str:
    """Section 4.6.1: a macro-string that ends in a macro or in "." and a top label."""
    tokens = _tokens(spec, word)
    if not tokens:
        raise _perm(f"empty domain in {word}")
    for token in tokens:
        macro = _MACRO.fullmatch(token)
        if macro and macro[1] and macro[1].lower() not in _DOMAIN_LETTERS:
            raise _perm(f"macro {token} is allowed only in exp text: {word}")
    if tokens[-1].startswith("%"):  # ends in a macro-expand
        return spec
    _, dot, top = spec.removesuffix(".").rpartition(".")
    if not dot or not _TOPLABEL.fullmatch(top):
        raise _perm(f"domain does not end in a top label: {word}")
    return spec


# ---------------------------------------------------------------- names


def _valid_name(name: str) -> bool:
    """A name a DNS query can be made of, with at least two labels (section 4.3)."""
    labels = name.removesuffix(".").split(".")
    return (
        len(labels) > 1
        and all(0 < len(label) <= 63 for label in labels)
        and not name.startswith("[")
    )


def _truncate(name: str) -> str:
    """Section 7.3: a name longer than 253 characters loses labels from the left."""
    name = name.removesuffix(".")
    while len(name) > 253 and "." in name:
        name = name.split(".", 1)[1]
    return name


# ---------------------------------------------------------------- evaluation


@dataclass(slots=True)
class _Check:
    ctx: Context
    ip: Address
    local: str
    sender_domain: str
    helo: str
    lookups: int = 0
    voids: int = 0
    _validated: list[str] | None = None  # asked once per check, for ptr and the p macro

    @property
    def v6(self) -> bool:
        return isinstance(self.ip, ipaddress.IPv6Address)

    async def query(self, name: str, rtype: str) -> Answer:
        answer = await self.ctx.dns.query(name, rtype)
        if answer.status is Status.FAILED:
            raise _temp(answer)
        return answer

    def void(self, answer: Answer) -> None:
        if answer.status in (Status.NXDOMAIN, Status.NOANSWER) or not answer.records:
            self.voids += 1
            if self.voids > VOID_LIMIT:
                raise _perm(f"more than {VOID_LIMIT} lookups found nothing ({answer.name})")

    def count(self, term: str) -> None:
        self.lookups += 1
        if self.lookups > LOOKUP_LIMIT:
            raise _perm(f"more than {LOOKUP_LIMIT} DNS lookups (at {term})")

    async def record(self, domain: str) -> Evidence | None:
        """Section 4.4 and 4.5: the domain's one SPF record, None when it has none."""
        answer = await self.query(domain, "TXT")
        records = [r for r in answer.records if r[:6].lower() == "v=spf1" and r[6:7] in ("", " ")]
        if len(records) > 1:
            raise _perm(f"{norm(domain)} publishes {len(records)} SPF records")
        if not records:
            return None
        return Evidence(answer.name, "TXT", records[0], self.ctx.checked_at)

    async def evaluate(self, domain: str, evidence: Evidence) -> Verdict:
        """One record against the address: the first matching term decides, then redirect,
        then neutral (section 4.7)."""
        record = _parse(evidence)
        for term in record.terms:
            if term.counts:
                self.count(term.text)
            if term.name == "include":
                inner = await self.include(term, domain)
                if inner is not None:  # the term that matched is inside, the result is ours
                    return replace(inner, result=term.qualifier)
            elif await self.matches(term, domain):
                return Verdict(term.qualifier, term.text, evidence)
        if record.redirect is not None and not record.has_all:
            self.count(f"redirect={record.redirect}")
            target = await self.target(record.redirect, domain)
            if target is None:
                raise _perm(f"redirect={record.redirect} names no domain")
            found = await self.record(target)
            if found is None:
                raise _perm(f"redirect to {target}, which has no SPF record")
            outcome = await self.evaluate(target, found)
            return replace(outcome, path=(found, *outcome.path))
        return Verdict(Result.NEUTRAL, None, evidence)

    async def matches(self, term: _Term, domain: str) -> bool:
        """Section 5, every mechanism but include."""
        if term.name == "all":
            return True
        if term.network is not None:  # ip4 and ip6
            return self.ip in term.network
        target = await self.target(term.domain, domain)
        if target is None:
            return False
        ask = {"a": self.a, "mx": self.mx, "ptr": self.ptr, "exists": self.exists}[term.name]
        return await ask(target, term)

    async def include(self, term: _Term, domain: str) -> Verdict | None:
        """Section 5.2: pass matches, and the inner Verdict says what matched; fail, softfail
        and neutral do not match; none is a permerror."""
        target = await self.target(term.domain, domain)
        if not target:
            return None
        found = await self.record(target)
        if found is None:
            raise _perm(f"{term.text}: {target} has no SPF record")
        inner = await self.evaluate(target, found)
        if inner.result is not Result.PASS:
            return None
        return replace(inner, path=(found, *inner.path))

    async def a(self, target: str, term: _Term) -> bool:
        """Section 5.3."""
        rtype = "AAAA" if self.v6 else "A"
        answer = await self.query(target, rtype)
        self.void(answer)
        return self.in_any(answer.records, term)

    def in_any(self, records: Sequence[str], term: _Term) -> bool:
        prefix = term.cidr6 if self.v6 else term.cidr4
        for record in records:
            try:
                network = ipaddress.ip_network(f"{record}/{prefix}", strict=False)
            except ValueError:
                continue
            if self.ip in network:
                return True
        return False

    async def mx(self, target: str, term: _Term) -> bool:
        """Section 5.4: the addresses of up to ten MX hosts."""
        answer = await self.query(target, "MX")
        self.void(answer)
        if len(answer.records) > MX_LIMIT:
            raise _perm(f"{term.text}: {target} has more than {MX_LIMIT} MX records")
        rtype = "AAAA" if self.v6 else "A"
        for record in answer.records:
            host = record.partition(" ")[2]
            if not host or not _valid_name(host):  # a null MX (RFC 7505) names no host
                continue
            addresses = await self.query(host, rtype)
            if self.in_any(addresses.records, term):
                return True
        return False

    async def ptr(self, target: str, term: _Term) -> bool:
        """Section 5.5: a validated name of the address that is the target or under it."""
        target = norm(target)
        return any(n == target or n.endswith(f".{target}") for n in await self.validated())

    async def exists(self, target: str, term: _Term) -> bool:
        """Section 5.7: any A record, whatever the address's version."""
        answer = await self.query(target, "A")
        self.void(answer)
        return bool(answer.records)

    async def validated(self) -> list[str]:
        """The names the address's PTR records give that lead back to the address (section
        5.5), at most ten names asked. A failed PTR lookup validates nothing, and a name whose
        address lookup fails is skipped."""
        if self._validated is not None:
            return self._validated
        names: list[str] = []
        answer = await self.ctx.dns.query(self.ip.reverse_pointer, "PTR")
        if answer.status is not Status.FAILED:
            self.void(answer)
            rtype = "AAAA" if self.v6 else "A"
            for name in answer.records[:PTR_LIMIT]:
                if not _valid_name(name):
                    continue
                addresses = await self.ctx.dns.query(name, rtype)
                if any(_same(record, self.ip) for record in addresses.records):
                    names.append(norm(name))
        self._validated = names
        return names

    async def target(self, spec: str | None, domain: str) -> str | None:
        """The target-name: the spec expanded, or the current domain when there is none. A
        name no query can be made of matches nothing (the suite allows fail or permerror here,
        and RFC 7208 leaves it open)."""
        if spec is None:
            return domain
        name = _truncate(await self.expand(spec, domain))
        return name if _valid_name(name) else None

    async def expand(self, spec: str, domain: str) -> str:
        """Section 7: the macros of a domain-spec."""
        out: list[str] = []
        for token in _tokens(spec, spec):
            if not token.startswith("%"):
                out.append(token)
            elif token == "%%":
                out.append("%")
            elif token == "%_":
                out.append(" ")
            elif token == "%-":
                out.append("%20")
            else:
                out.append(await self.macro(token, domain))
        return "".join(out)

    async def macro(self, token: str, domain: str) -> str:
        match = _MACRO.fullmatch(token)
        assert match and match[1]
        letter, digits, reverse, delimiters = match[1], match[2], match[3], match[4]
        value = await self.letter(letter.lower(), domain)
        parts = re.split(f"[{re.escape(delimiters or '.')}]", value)
        if reverse:
            parts.reverse()
        if digits:
            keep = int(digits)
            if keep == 0:
                raise _perm(f"macro {token} keeps no parts")
            parts = parts[-keep:]
        value = ".".join(parts)
        return quote(value, safe="-._~") if letter.isupper() else value

    async def letter(self, letter: str, domain: str) -> str:
        if letter == "p":
            return await self.p(domain)
        if letter == "i" and isinstance(self.ip, ipaddress.IPv6Address):
            return ".".join(self.ip.exploded.replace(":", ""))  # one label per nibble
        return {
            "s": f"{self.local}@{self.sender_domain}",
            "l": self.local,
            "o": self.sender_domain,
            "d": norm(domain),
            "i": str(self.ip),
            "v": "ip6" if self.v6 else "in-addr",
            "h": self.helo,
        }[letter]

    async def p(self, domain: str) -> str:
        """Section 7.3: a validated name, the domain itself first, then one under it."""
        names = await self.validated()
        domain = norm(domain)
        for name in names:
            if name == domain:
                return name
        for name in names:
            if name.endswith(f".{domain}"):
                return name
        return names[0] if names else "unknown"


def _same(record: str, address: Address) -> bool:
    try:
        return ipaddress.ip_address(record) == address
    except ValueError:
        return False
