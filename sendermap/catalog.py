"""The vendor catalog, and every rule for matching a record to a service.

All knowledge about services lives in data/vendors.json, one block per service. Every pattern in
a block carries a proof: a live domain that publishes it, the record, and the date it was
checked. Loading refuses a pattern without one. This module checks the proofs, indexes the
patterns and applies the matching rules, each of which was learned on a live domain.

data/vendors_pending.json holds patterns with no proof yet. Nothing here reads it.

A block may carry `sending_ip`: one address the service sends from, proven by the service's own
SPF record publishing a range that holds it, or by a host of its whose A record is the address.
SPF evaluation asks a domain's record about that address.

A block may also carry `aliases`: other names a client calls the service by, with no proof, since
an alias matches text a person typed and nothing in DNS.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from typing import Any

from . import proofs
from .dns import norm
from .model import Need
from .proofs import Proof
from .selectors import Rule, build_dictionary, parse_rules

_HOST_FIELDS = (
    "spf_includes",
    "mx",
    "dkim_cname",
    "reporting",
    "return_path",
    "tracking",
    "delegation_ns",
)
# Every field whose entries are a value and its proof. other_cname entries are a label, a
# target and a proof.
PATTERN_FIELDS = (
    *_HOST_FIELDS,
    "verification_txt",
    "networks",
    "sending_ip",
    "website",
    "subprocessor_names",
)


@dataclass(frozen=True, slots=True)
class Pattern:
    """One vendor pattern and the proof that it was seen live. `label` is set only for an
    other_cname pattern, whose value is the CNAME target expected at that label."""

    vendor: str
    field: str
    value: str
    proof: Proof
    label: str | None = None


# A setup item's record, and the block fields whose values it may name.
SETUP_RECORDS: dict[str, tuple[str, ...]] = {
    "spf": ("spf_includes",),
    "dkim": ("selectors", "dkim_cname"),
    "return_path": ("return_path",),
    "tracking": ("tracking",),
    "mx": ("mx",),
}


@dataclass(frozen=True, slots=True)
class SetupRule:
    """One record a vendor's documentation says a complete setup publishes: which record, whether
    it is needed, the block's own pattern values the setup publishes (an include host, the
    current selector names, a CNAME target, an MX host), and the documentation page that names
    every one of them."""

    vendor: str
    record: str
    need: Need
    values: tuple[str, ...]
    proof: Proof
    note: str | None = None

    @property
    def selectors(self) -> tuple[str, ...]:
        """For a DKIM item, the values that are selector names, in order."""
        return tuple(v for v in self.values if "." not in v) if self.record == "dkim" else ()


@dataclass(frozen=True, slots=True)
class HostTable:
    """Hostname patterns to services. A pattern matches the host itself or any name under it,
    on a label boundary, and the longest match wins: sendgrid.net.evil.example is not SendGrid,
    and u161779.wl030.sendgrid.net (Klaviyo's own SendGrid account) beats sendgrid.net."""

    patterns: dict[str, str] = field(default_factory=dict)

    def match(self, host: str | None) -> str | None:
        if not host:
            return None
        labels = norm(host).split(".")
        for start in range(len(labels)):  # longest suffix first
            service = self.patterns.get(".".join(labels[start:]))
            if service:
                return service
        return None


@dataclass(frozen=True, slots=True)
class Catalog:
    services: dict[str, dict[str, Any]]
    patterns: tuple[Pattern, ...]
    rules: tuple[Rule, ...]  # every vendor's DKIM selector rules, in file order
    tables: dict[str, HostTable]
    selectors: dict[str, str]  # a selector name to the first rule's vendor that claims it
    tokens: tuple[tuple[re.Pattern[str], str], ...]
    other_cnames: dict[str, HostTable]
    networks: dict[str, str]
    clouds: dict[str, str]
    generic_selectors: frozenset[str]
    short_selectors_allowed: frozenset[str]
    cname_only_selectors: frozenset[str]
    hosted_spf: frozenset[str]
    flattening_spf: frozenset[str]
    cname_labels: tuple[str, ...]
    tracking_labels: frozenset[str]
    sending_labels: tuple[str, ...]
    website: dict[str, str]
    # The names a sending service goes by, as a subprocessor page would list it, to the service.
    # A name that is also an ordinary word ("Kit", "Wix") is simply not listed.
    subprocessor_names: dict[str, str]
    # Each vendor's documented setup, one rule per record, in file order.
    setups: dict[str, tuple[SetupRule, ...]] = field(default_factory=dict)
    # Every vendor's name and aliases, normalised, to the vendor.
    names: dict[str, str] = field(default_factory=dict)
    # The one address each service with a sending_ip sends from, in file order.
    sending_ips: dict[str, str] = field(default_factory=dict)
    # Selector names that credit their vendor only where something else already shows it.
    backed_only_selectors: dict[str, str] = field(default_factory=dict)
    backed_only_proofs: dict[str, Proof] = field(default_factory=dict)

    # ------------------------------------------------------------ lookups by record

    def spf(self, host: str) -> str | None:
        return self.tables["spf_includes"].match(host)

    def mx(self, host: str) -> str | None:
        return self.tables["mx"].match(host)

    def reporting(self, host: str) -> str | None:
        return self.tables["reporting"].match(host)

    def delegation(self, host: str) -> str | None:
        """The service whose nameserver `host` is, when a subdomain is delegated to it."""
        return self.tables["delegation_ns"].match(host)

    def network(self, asn: str) -> str | None:
        return self.networks.get(asn.upper())

    def token(self, record: str) -> str | None:
        """The service whose verification token this apex TXT record is, if any."""
        text = record.strip().lower()
        for pattern, service in self.tokens:
            m = pattern.match(text)
            # A prefix with nothing after it verifies nothing.
            if m and len(text[m.end() :].strip()) >= 4:
                return service
        return None

    def dkim_cname(self, chain: Iterable[str]) -> str | None:
        """The first hop of a DKIM alias chain that names a service."""
        return next(filter(None, map(self.tables["dkim_cname"].match, chain)), None)

    def dkim_key(self, selector: str, chain: tuple[str, ...], backed: str | None) -> str | None:
        """Who a published DKIM key belongs to.

        1. A CNAME into the service's zone, always: the service hosts the key.
        2. selector1 and selector2 name nobody without that CNAME (Microsoft 365 publishes them
           only as aliases into its own zone).
        3. A backed only name credits its vendor only when backed names that same vendor, and
           names nobody otherwise. s1 and s2 are plain names many hosts use, so Klaviyo earns
           them only where SPF, MX or an NS delegation already shows Klaviyo.
        4. backed: a service the domain's SPF or MX already shows, whose selector list has this
           name. k1 on a Mailgun domain is Mailgun, not Mailchimp.
        5. The name table, unless the name is generic.
        """
        if by_cname := self.dkim_cname(chain):
            return by_cname
        name = selector.lower()
        if name in self.cname_only_selectors:
            return None
        if owner := self.backed_only_selectors.get(name):
            return owner if backed == owner else None
        if backed:
            return backed
        if self.is_generic(name):
            return None
        return self.selectors.get(name)

    def is_generic(self, selector: str) -> bool:
        s = selector.lower()
        return s in self.generic_selectors or (
            len(s) <= 2 and s not in self.short_selectors_allowed
        )

    def label_cname(self, label: str, target: str) -> tuple[str, str] | None:
        """(service, "return path" | "tracking" | label) for a CNAME at <label>.<domain>."""
        label = label.lower()
        if label in self.other_cnames:
            service = self.other_cnames[label].match(target)
            return (service, label) if service else None
        order = [("tracking", "tracking"), ("return path", "return_path")]
        if label not in self.tracking_labels:
            order.reverse()
        for kind, table in order:
            if service := self.tables[table].match(target):
                return service, kind
        return None

    def website_services(self, html: str, loaded: Iterable[str]) -> dict[str, tuple[str, bool]]:
        """{service: (host, loaded)} for every service whose website host the page loads a
        script or stylesheet from (loaded is True), or otherwise mentions anywhere in its HTML
        (loaded is False). `loaded` is the hosts of the page's script src and link href URLs."""
        hosts = [norm(h) for h in loaded]
        page = html.lower()
        found: dict[str, tuple[str, bool]] = {}
        for pattern, service in self.website.items():
            if found.get(service, ("", False))[1]:
                continue
            if host := next((h for h in hosts if h == pattern or h.endswith("." + pattern)), None):
                found[service] = (host, True)
            elif service not in found and re.search(rf"(?<![a-z0-9-]){re.escape(pattern)}\b", page):
                found[service] = (pattern, False)
        return found

    def selectors_of(self, service: str) -> frozenset[str]:
        return frozenset(n for r in self.rules if r.vendor == service for n in r.shape.expand())

    def backs(self, service: str) -> frozenset[str]:
        """The selector names a claim for `service` backs: its own list, less any backed only
        name another vendor owns, plus the backed only names it owns."""
        own = {n for n, v in self.backed_only_selectors.items() if v == service}
        listed = {n for n in self.selectors_of(service) if n not in self.backed_only_selectors}
        return frozenset(listed | own)

    @property
    def probe_selectors(self) -> tuple[str, ...]:
        """The DKIM sweep: every name the selector rules claim, in rule order, then the generic
        names, which credit nobody by name but show a key is there."""
        return tuple(
            dict.fromkeys((*build_dictionary(self.rules), *sorted(self.generic_selectors)))
        )

    def named(self, text: str) -> str | None:
        """The vendor a person means by `text`: its name or one of its aliases, exactly, after
        both are normalised. Nothing fuzzier."""
        return self.names.get(normalise(text))

    def sending_ip_host(self, service: str) -> str:
        """The record that proves the service's sending address: its SPF record host or the
        host whose address it is. SPF evaluation gives it as the HELO name."""
        return next(
            norm(p.proof.record)
            for p in self.patterns
            if p.vendor == service and p.field == "sending_ip"
        )

    def category(self, service: str) -> str:
        return str(self.services.get(service, {}).get("category", "Other"))

    def is_hosted_spf(self, service: str | None) -> bool:
        return service in self.hosted_spf

    def spf_sources(self) -> dict[str, list[str]]:
        """{service: its SPF include hosts} for services whose includes are real records,
        not zones that only hold per-customer names."""
        return {
            name: [h for h in block.get("spf_includes", ()) if "." in h]
            for name, block in self.services.items()
            if block.get("spf_includes")
        }

    def __iter__(self) -> Iterator[str]:
        return iter(self.services)


@cache
def load() -> Catalog:
    raw = json.loads(resources.files(__package__).joinpath("data/vendors.json").read_text())
    return build(raw)


def build(raw: dict[str, Any]) -> Catalog:
    """Index the vendor data. ValueError if any pattern lacks a valid proof."""
    patterns = tuple(p for name, block in raw["vendors"].items() for p in _patterns(name, block))
    selector_rules = parse_rules(raw["vendors"])
    services = {name: _values(block) for name, block in raw["vendors"].items()}
    rules: dict[str, Any] = raw["rules"]
    backed_only = _backed_only(rules.get("backed_only_selectors", {}), raw["vendors"], rules)
    tables = {f: HostTable({}) for f in _HOST_FIELDS}
    selectors = {n: claims[0].vendor for n, claims in build_dictionary(selector_rules).items()}
    tokens: list[tuple[re.Pattern[str], str]] = []
    other: dict[str, HostTable] = {}
    networks: dict[str, str] = {}
    website: dict[str, str] = {}
    named: dict[str, str] = {}
    for name, block in services.items():
        for text in block.get("subprocessor_names", ()):
            named[text] = name
        for host in block.get("website", ()):
            website[host.lower()] = name
        for f in _HOST_FIELDS:
            for pattern in block.get(f, ()):
                tables[f].patterns[norm(pattern)] = name
        for pattern in block.get("verification_txt", ()):
            tokens.append((re.compile(pattern, re.IGNORECASE), name))
        for entry in block.get("other_cname", ()):
            other.setdefault(entry["label"], HostTable({})).patterns[norm(entry["target"])] = name
        for asn in block.get("networks", ()):
            networks[asn.upper()] = name
    return Catalog(
        services=services,
        patterns=patterns,
        rules=selector_rules,
        tables=tables,
        selectors=selectors,
        tokens=tuple(tokens),
        other_cnames=other,
        networks=networks,
        clouds={k.upper(): v for k, v in rules.get("cloud_networks", {}).items()},
        generic_selectors=frozenset(rules["generic_selectors"]),
        short_selectors_allowed=frozenset(rules["short_selectors_allowed"]),
        cname_only_selectors=frozenset(rules["cname_only_selectors"]),
        hosted_spf=frozenset(rules["hosted_spf"]),
        flattening_spf=frozenset(rules.get("flattening_spf", ())),
        cname_labels=tuple(rules["cname_labels"]),
        tracking_labels=frozenset(rules["tracking_labels"]),
        sending_labels=tuple(rules["sending_labels"]),
        website=website,
        subprocessor_names=named,
        setups={
            name: setup
            for name, block in raw["vendors"].items()
            if (setup := _setup(name, block, selector_rules))
        },
        names=_names(raw["vendors"]),
        sending_ips=_sending_ips(services),
        backed_only_selectors={n: v for n, (v, _) in backed_only.items()},
        backed_only_proofs={n: proof for n, (_, proof) in backed_only.items()},
    )


# Words a company name may start or end with that do not tell one service from another.
_LEADING = ("the",)
_TRAILING = ("inc", "llc", "ltd")


def normalise(text: str) -> str:
    """A service name as a person might type it, reduced for exact matching: casefolded,
    spaces and punctuation gone, a leading "the" and a trailing "inc", "llc" or "ltd" dropped
    when other words remain. "The Mailchimp, Inc." and "mailchimp" are one name."""
    words = re.findall(r"[^\W_]+", text.casefold())
    if len(words) > 1 and words[0] in _LEADING:
        words = words[1:]
    if len(words) > 1 and words[-1] in _TRAILING:
        words = words[:-1]
    return "".join(words)


def _names(vendors: dict[str, Any]) -> dict[str, str]:
    """Each vendor's name and aliases, normalised, to the vendor. ValueError for an alias that
    is not a string, normalises to nothing, or names a vendor already named the same way (its
    own name or another vendor's name or alias)."""
    names: dict[str, str] = {}
    for vendor, block in vendors.items():
        aliases = block.get("aliases", [])
        if not isinstance(aliases, list):
            raise ValueError(f"{vendor} aliases: not a list")
        for text in (vendor, *aliases):
            if not isinstance(text, str) or not (key := normalise(text)):
                raise ValueError(f"{vendor} alias {text!r}: not a name")
            if key in names:
                raise ValueError(f"{vendor} alias {text!r}: already names {names[key]}")
            names[key] = vendor
    return names


def _backed_only(
    raw: dict[str, Any], vendors: dict[str, Any], rules: dict[str, Any]
) -> dict[str, tuple[str, Proof]]:
    """{selector: (vendor, proof)} for the backed only names. ValueError for a vendor not in
    the file, a name also cname only, or a proof that is not a key at that name."""
    found: dict[str, tuple[str, Proof]] = {}
    for name, entry in raw.items():
        where = f"backed only selector {name}"
        vendor = entry.get("vendor")
        if vendor not in vendors:
            raise ValueError(f"{where}: vendor {vendor!r} is not in the file")
        if name.lower() != name or name in rules["cname_only_selectors"]:
            raise ValueError(f"{where}: not a lowercase name outside cname_only_selectors")
        if not entry.get("proof"):
            raise ValueError(f"{where}: no proof")
        proof = proofs.parse(entry["proof"])
        proofs.check(where, proof)
        if proofs.normalise(proof.record) != f"{name}._domainkey.{proofs.normalise(proof.domain)}":
            raise ValueError(f"{where}: proof record {proof.record!r} is not {name}._domainkey")
        found[name] = (vendor, proof)
    return found


def _sending_ips(services: dict[str, dict[str, Any]]) -> dict[str, str]:
    """{service: its one sending address}. ValueError for more than one, or one that is not an
    IP address."""
    found: dict[str, str] = {}
    for name, block in services.items():
        values = block.get("sending_ip", ())
        if len(values) > 1:
            raise ValueError(f"{name} sending_ip: one address, not {len(values)}")
        for value in values:
            try:
                found[name] = str(ipaddress.ip_address(value))
            except ValueError:
                raise ValueError(f"{name} sending_ip {value!r}: not an IP address") from None
    return found


def _setup(vendor: str, block: dict[str, Any], rules: tuple[Rule, ...]) -> tuple[SetupRule, ...]:
    """The block's setup list, each item checked: a known record, a known need, values that are
    patterns of this block for that record (none when nothing is needed, at least one
    otherwise), at most one item per record, and a dated proof on an https page of the proof's
    domain."""
    found: list[SetupRule] = []
    for raw in block.get("setup", ()):
        record = raw.get("record")
        where = f"{vendor} setup {record}"
        if record not in SETUP_RECORDS:
            raise ValueError(f"{where}: record is not one of {', '.join(SETUP_RECORDS)}")
        if any(rule.record == record for rule in found):
            raise ValueError(f"{where}: listed twice")
        try:
            need = Need(raw.get("need"))
        except ValueError:
            raise ValueError(f"{where}: need is not required, optional or none") from None
        values = tuple(str(v) for v in raw.get("values", ()))
        if need is Need.NONE and values:
            raise ValueError(f"{where}: a record that is not needed names no values")
        if need is not Need.NONE and not values:
            raise ValueError(f"{where}: a needed record names its values")
        own = _own_values(vendor, block, record, rules)
        if strays := [v for v in values if v.lower() not in own]:
            raise ValueError(f"{where}: {', '.join(strays)} is not a pattern of this block")
        if not raw.get("proof"):
            raise ValueError(f"{where}: no proof")
        proof = proofs.parse(raw["proof"])
        proofs.check(where, proof)
        proofs.check_record(where, "setup", proof)
        found.append(SetupRule(vendor, record, need, values, proof, raw.get("note")))
    return tuple(found)


def _own_values(
    vendor: str, block: dict[str, Any], record: str, rules: tuple[Rule, ...]
) -> set[str]:
    """The values this block's patterns hold for one setup record, lowercase."""
    own: set[str] = set()
    for f in SETUP_RECORDS[record]:
        if f == "selectors":
            own |= {n for r in rules if r.vendor == vendor for n in r.shape.expand()}
        else:
            own |= {str(e["value"]).lower() for e in block.get(f, ())}
    return own


def _patterns(vendor: str, block: dict[str, Any]) -> list[Pattern]:
    """Every pattern in one vendor block, each with its proof checked."""
    found: list[Pattern] = []
    for kind in (*PATTERN_FIELDS, "other_cname"):
        for entry in block.get(kind, ()):
            if not isinstance(entry, dict) or not entry.get("proof"):
                raise ValueError(f"{vendor} {kind} {entry!r}: no proof")
            label = entry.get("label") if kind == "other_cname" else None
            value = entry["target"] if kind == "other_cname" else entry["value"]
            where = f"{vendor} {kind} {value}"
            proof = proofs.parse(entry["proof"])
            proofs.check(where, proof)
            proofs.check_record(where, kind, proof)
            found.append(Pattern(vendor, kind, value, proof, label))
    return found


def _values(block: dict[str, Any]) -> dict[str, Any]:
    """The block with each proofed entry reduced to what matching uses: its value, or for
    other_cname its label and target."""
    plain = dict(block)
    for kind in PATTERN_FIELDS:
        if kind in block:
            plain[kind] = [entry["value"] for entry in block[kind]]
    if "other_cname" in block:
        plain["other_cname"] = [
            {"label": e["label"], "target": e["target"]} for e in block["other_cname"]
        ]
    return plain
