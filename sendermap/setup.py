"""Setups: what a vendor's documentation says a complete setup publishes, and whether the map
shows it.

A setup costs no query. It is read from what the map already asked: the claims, the answers the
sources kept (`Read`), what was asked at each name (`Checked`), the absences and the gaps. Each
item names only what was asked: a record the map did not ask for is not checked, never missing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .catalog import Catalog, SetupRule
from .dns import Status
from .model import (
    Absence,
    Checked,
    Claim,
    Denial,
    Evidence,
    Finding,
    Gap,
    Kind,
    Need,
    Outcome,
    Read,
    Service,
    Setup,
    SetupItem,
    Severity,
    State,
    Tier,
)
from .sources.dkim import NO_SELECTORS

KEY_KINDS = frozenset({Kind.DKIM_CNAME, Kind.DKIM_NAME})
BROKEN_KEY_KINDS = frozenset({Kind.DKIM_REVOKED, Kind.DKIM_DANGLING})
# Any claim that the domain's SPF authorizes the service counts: an include, a range it owns,
# or a pass when SPF evaluation asked about one of its addresses.
SPF_KINDS = frozenset({Kind.SPF_INCLUDE, Kind.SPF_NETWORK, Kind.SPF_EVALUATED})
CNAME_KINDS = {"return_path": Kind.RETURN_PATH, "tracking": Kind.TRACKING}
MX_KINDS = frozenset({Kind.MX, Kind.SUBDOMAIN_MAILBOX, Kind.SUBDOMAIN_MX})
RECEIVERS = frozenset({"Mailbox", "Security gateway"})
# How each record reads in a setup line.
WORDS = {
    "spf": "SPF",
    "dkim": "DKIM",
    "return_path": "bounce CNAME",
    "tracking": "tracking CNAME",
    "mx": "MX",
}


@dataclass(frozen=True, slots=True)
class Asked:
    """Everything a setup reads, gathered once per map."""

    domain: str
    reads: tuple[Read, ...]
    checked: Mapping[str, Checked]
    absences: tuple[Absence, ...]
    gaps: tuple[Gap, ...]

    def read(self, record: str, where: str, name: str = "") -> Read | None:
        return next(
            (r for r in self.reads if (r.record, r.where, r.name) == (record, where, name)), None
        )


def build(
    services: Iterable[Service],
    catalog: Catalog,
    *,
    domain: str,
    reads: tuple[Read, ...],
    checked: Iterable[Checked],
    absences: tuple[Absence, ...],
    gaps: tuple[Gap, ...],
) -> tuple[tuple[Service, ...], tuple[Finding, ...]]:
    """Each service with its setups, and the findings they raise."""
    asked = Asked(domain, reads, {c.where: c for c in checked}, absences, gaps)
    out: list[Service] = []
    findings: list[Finding] = []
    for service in services:
        rules = catalog.setups.get(service.name, ())
        if not rules:
            out.append(service)
            continue
        setups = tuple(
            _setup(service, where, rules, catalog, asked) for where in _names(service, domain)
        )
        out.append(
            Service(
                service.name, service.category, service.tier, service.role, service.claims, setups
            )
        )
        findings += _findings(service, setups, domain)
    return tuple(out), tuple(findings)


def _names(service: Service, domain: str) -> list[str]:
    """Every name the service has claims at, the domain first, then the rest in order, except a
    bounce domain: a name below another of the service's names where the service's MX takes the
    replies and bounces. That name is the return path of the setup above it, not a setup of its
    own, so its MX counts there and its own DKIM is never judged."""
    names = {c.where for c in service.claims}
    return sorted(names - _bounce_domains(service), key=lambda n: (n != domain, n))


def _bounce_domains(service: Service) -> set[str]:
    names = {c.where for c in service.claims}
    return {
        c.where
        for c in service.claims
        if c.kind is Kind.SUBDOMAIN_MX and any(_below(c.where, n) for n in names)
    }


def _below(name: str, parent: str) -> bool:
    return name.endswith("." + parent)


def _setup(
    service: Service, where: str, rules: tuple[SetupRule, ...], catalog: Catalog, asked: Asked
) -> Setup:
    claims = [c for c in service.claims if c.where == where]
    bounces = _bounce_domains(service)
    claims += [
        c
        for c in service.claims
        if c.kind is Kind.SUBDOMAIN_MX and c.where in bounces and _below(c.where, where)
    ]
    items = tuple(_item(rule, claims, where, catalog, asked) for rule in rules)
    required = [i.state for i in items if i.need is Need.REQUIRED]
    complete: bool | None
    if any(s in (State.MISSING, State.BROKEN) for s in required):
        complete = False
    elif any(s is State.NOT_CHECKED for s in required):
        complete = None
    else:
        complete = True
    return Setup(service.name, where, items, complete)


def _item(
    rule: SetupRule, claims: list[Claim], where: str, catalog: Catalog, asked: Asked
) -> SetupItem:
    """One item at `where`. `claims` are the service's claims there, and the MX claims of the
    bounce domains below it, which only the bounce item reads."""
    if rule.need is Need.NONE:
        return SetupItem(rule.record, rule.need, State.NOT_NEEDED)
    if rule.record == "return_path":
        return _cname(rule, claims, where, asked)
    here = [c for c in claims if c.where == where]
    if rule.record == "dkim":
        return _dkim(rule, here, where, catalog, asked)
    if rule.record == "spf":
        return _spf(rule, here, where, asked)
    if rule.record == "mx":
        return _mx(rule, here, where, asked)
    return _cname(rule, here, where, asked)


def _evidence(claims: Iterable[Claim]) -> tuple[Evidence, ...]:
    return tuple(dict.fromkeys(c.evidence for c in claims))


def _not_checked(rule: SetupRule, asked: str, detail: str) -> SetupItem:
    return SetupItem(rule.record, rule.need, State.NOT_CHECKED, asked=asked, detail=detail)


def _spf(rule: SetupRule, claims: list[Claim], where: str, asked: Asked) -> SetupItem:
    question = f"TXT at {where}"
    if found := [c for c in claims if c.kind in SPF_KINDS]:
        return SetupItem(rule.record, rule.need, State.PRESENT, _evidence(found), question)
    read = asked.read("spf", where)
    if read is None:
        return _not_checked(rule, question, f"SPF at {where} was not read")
    # Evaluation asked the record about one of the vendor's addresses and it did not pass.
    if read.outcome in (Outcome.FOUND, Outcome.UNREADABLE) and (
        evaluated := asked.read("spf_eval", where, rule.vendor)
    ):
        return SetupItem(
            rule.record, rule.need, State.MISSING, evaluated.evidence, question, evaluated.reason
        )
    if read.outcome is Outcome.FAILED or read.outcome is Outcome.UNREADABLE:
        return SetupItem(
            rule.record, rule.need, State.NOT_CHECKED, read.evidence, question, read.reason
        )
    if read.outcome is Outcome.BROKEN:
        detail = f"{len(read.evidence)} SPF records, so SPF fails for every message"
        return SetupItem(rule.record, rule.need, State.BROKEN, read.evidence, question, detail)
    detail = (
        "no SPF record"
        if read.outcome is Outcome.NONE
        else f"the record does not authorize {_listed(rule.values)}"
    )
    return SetupItem(rule.record, rule.need, State.MISSING, read.evidence, question, detail)


def _mx(rule: SetupRule, claims: list[Claim], where: str, asked: Asked) -> SetupItem:
    question = f"MX at {where}"
    if found := [c for c in claims if c.kind in MX_KINDS]:
        return SetupItem(rule.record, rule.need, State.PRESENT, _evidence(found), question)
    read = asked.read("mx", where)
    if read is None:
        return _not_checked(rule, question, f"MX at {where} was not read")
    if read.outcome is Outcome.FAILED:
        return _not_checked(rule, question, read.reason)
    detail = (
        "no MX record"
        if read.outcome is Outcome.NONE
        else f"no MX host under {_listed(rule.values)}"
    )
    return SetupItem(rule.record, rule.need, State.MISSING, read.evidence, question, detail)


def _cname(rule: SetupRule, claims: list[Claim], where: str, asked: Asked) -> SetupItem:
    kind = CNAME_KINDS[rule.record]
    if found := [c for c in claims if c.kind is kind or c.where != where]:
        question = ", ".join(
            f"{c.evidence.rtype} at {c.evidence.name}" for c in dict.fromkeys(found)
        )
        return SetupItem(rule.record, rule.need, State.PRESENT, _evidence(found), question)
    reads = [r for r in asked.reads if r.record == "label" and r.where == where]
    labels = asked.checked[where].labels if where in asked.checked else ()
    question = f"CNAME at {len(labels)} labels under {where}"
    if not labels or not reads:
        return _not_checked(rule, f"CNAME labels under {where}", f"no label was asked at {where}")
    if unreadable := [r for r in reads if r.outcome is Outcome.UNREADABLE]:
        return _not_checked(rule, question, unreadable[0].reason)
    if failed := [r.name for r in reads if r.outcome is Outcome.FAILED]:
        return _not_checked(rule, question, f"lookup failed at {_listed(failed)}")
    evidence = tuple(e for r in reads for e in r.evidence)
    detail = f"no CNAME into {_listed(rule.values)} at the {len(labels)} labels asked"
    return SetupItem(rule.record, rule.need, State.MISSING, evidence, question, detail)


def _dkim(
    rule: SetupRule, claims: list[Claim], where: str, catalog: Catalog, asked: Asked
) -> SetupItem:
    current = rule.selectors
    base = f"_domainkey.{where}"
    question = (
        " and ".join(f"TXT at {s}.{base}" for s in current) if current else f"TXT under {base}"
    )
    if keys := [c for c in claims if c.kind in KEY_KINDS]:
        at = [_selector(c) for c in keys]
        listed = catalog.selectors_of(rule.vendor)
        detail = ""
        if current and not set(at) & set(current) and set(at) & listed:
            older = [s for s in dict.fromkeys(at) if s in listed]
            detail = (
                f"older setup: a key at {_listed(older)}; the current setup names "
                f"{_listed(current)}"
            )
        question = " and ".join(f"TXT at {c.evidence.name}" for c in keys)
        return SetupItem(rule.record, rule.need, State.PRESENT, _evidence(keys), question, detail)
    broken = [c.evidence for c in claims if c.kind in BROKEN_KEY_KINDS]
    broken += [
        e
        for s in current
        if (r := asked.read("dkim", where, s)) and r.outcome is Outcome.BROKEN
        for e in r.evidence
    ]
    if broken:
        detail = "the only key found is revoked, dangling or malformed"
        evidence = tuple(dict.fromkeys(broken))
        return SetupItem(rule.record, rule.need, State.BROKEN, evidence, question, detail)
    if wildcard := asked.read("dkim", where):
        return SetupItem(
            rule.record, rule.need, State.NOT_CHECKED, wildcard.evidence, question, wildcard.reason
        )
    return _unfound(rule, where, question, asked)


def _unfound(rule: SetupRule, where: str, question: str, asked: Asked) -> SetupItem:
    """A DKIM item with no key for the vendor: missing when every name the setup names was asked,
    or is covered by an absence, and nothing answered; otherwise not checked, with why."""
    current = rule.selectors
    record = asked.checked.get(where)
    if record is None or record.denial is Denial.WILDCARD:
        return _not_checked(rule, question, f"no DKIM name was asked at {where}")
    if not current:
        return _not_checked(rule, question, "the setup names no selector to ask")
    reads = {s: asked.read("dkim", where, s) for s in current if s in record.dkim_selectors}
    if failed := [s for s, r in reads.items() if r and r.outcome is Outcome.FAILED]:
        return _not_checked(rule, question, f"lookup failed at {_listed(failed)}")
    if other := [s for s, r in reads.items() if r is None]:
        detail = f"the key at {_listed(other)} is not credited to {rule.vendor}"
        return _not_checked(rule, question, detail)
    absent = next((a for a in asked.absences if a.asked == f"DKIM keys at {where}"), None)
    unasked = [s for s in current if s not in reads]
    if unasked and not (absent and absent.happened.startswith(NO_SELECTORS)):
        cap = next((g for g in asked.gaps if g.asked == f"DKIM selectors at {where}"), None)
        why = f"{cap.asked}: {cap.happened}" if cap else "not asked"
        return _not_checked(rule, question, f"{_listed(unasked)} not asked ({why})")
    none = [r for r in reads.values() if r]
    evidence = tuple(e for r in none for e in r.evidence)
    if absent:
        evidence = tuple(dict.fromkeys((*evidence, *absent.evidence)))
    detail = _missing_words(current, none, record, absent)
    return SetupItem(rule.record, rule.need, State.MISSING, evidence, question, detail)


def _missing_words(
    current: tuple[str, ...], none: list[Read], record: Checked, absent: Absence | None
) -> str:
    """The names that answered nothing, worded by how the zone denies a name: "selector1 and
    selector2 no such name"; or, where _domainkey itself does not exist, that no selector does."""
    if not none and absent:
        return f"{_listed(current)}: no selector exists under _domainkey.{record.where}"
    by_status: dict[str, list[str]] = {}
    for r in none:
        by_status.setdefault(r.evidence[0].value, []).append(r.name)
    words = "; ".join(_no_key(names, status) for status, names in by_status.items())
    if record.denial is Denial.NONE_BY_RCODE:
        words += "; this zone gives that answer for every name that does not exist"
    return words


# What a DKIM name's answer says, for one name and for several.
_ANSWERS = {
    Status.NXDOMAIN.value: ("a name that does not exist", "names that do not exist"),
    Status.NOANSWER.value: ("a name with no TXT record", "names with no TXT record"),
}


def _no_key(names: list[str], status: str) -> str:
    """'no key at google._domainkey, a name that does not exist'."""
    at = " or ".join(f"{n}._domainkey" for n in names)
    one, several = _ANSWERS.get(status, (status, status))
    return f"no key at {at}, {one if len(names) == 1 else several}"


def _selector(claim: Claim) -> str:
    return claim.evidence.name.split("._domainkey.", 1)[0].lower()


def _listed(items: Iterable[str]) -> str:
    names = list(items)
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def _findings(service: Service, setups: tuple[Setup, ...], domain: str) -> list[Finding]:
    """What a setup raises. A service known only by account traces raises one note asking
    whether the account is still used, and nothing about what its setup lacks. Broken items
    raise nothing new: the key findings already exist."""
    if all(c.kind.tier is Tier.ACCOUNT_ONLY for c in service.claims):
        return [
            Finding(
                Severity.NOTE,
                f"{service.name} shows only an account at {domain}",
                "The records name an account (a verification token, an autodiscover CNAME, or a "
                "revoked or dangling key) and nothing that sends or receives mail. Is the "
                "account still used? If not, remove its records.",
                _evidence(service.claims),
            )
        ]
    found: list[Finding] = []
    receives = service.category in RECEIVERS
    for setup in setups:
        in_mx = receives and any(
            c.kind is Kind.MX and c.where == setup.where for c in service.claims
        )
        for item in setup.items:
            if item.state is not State.MISSING:
                continue
            if in_mx and item.record in ("dkim", "spf"):
                found.append(_receiver(service.name, setup.where, item))
            elif item.need is Need.REQUIRED:
                found.append(_lacking(service.name, setup.where, item))
    return found


def _receiver(name: str, where: str, item: SetupItem) -> Finding:
    if item.record == "dkim":
        return Finding(
            Severity.RISK,
            f"{name} receives the domain's mail and does not sign it",
            f"{name} is in the MX records at {where}, so it is the domain's mailbox or gateway, "
            f"and its DKIM setup is missing: {item.detail}. Mail it sends as the domain carries "
            "no signature that aligns, so it passes DMARC on SPF alone.",
            item.evidence,
        )
    return Finding(
        Severity.RISK,
        f"{name} receives the domain's mail and is not in its SPF",
        f"{name} is in the MX records at {where}, and its SPF setup is missing: {item.detail}. "
        "Mail it sends as the domain fails SPF, so it passes DMARC on DKIM alone.",
        item.evidence,
    )


def _lacking(name: str, where: str, item: SetupItem) -> Finding:
    severity = Severity.WARNING if item.record in ("dkim", "spf") else Severity.NOTE
    return Finding(
        severity,
        f"{name} at {where} has no {WORDS[item.record]}",
        f"Its documented setup needs it and the map shows it missing: {item.detail}.",
        item.evidence,
    )


def line(setup: Setup) -> str:
    """One setup as a line, such as "Setup at <where>: SPF present, DKIM missing (selector1 and
    selector2 no such name), bounce CNAME not needed." for one name."""
    return f"Setup at {setup.where}: {', '.join(map(words, setup.items))}."


def words(item: SetupItem) -> str:
    """One item in words. An optional item that is missing reads "not used (optional, <what was
    asked>)", so a reader does not take an optional record for a fault."""
    if item.need is Need.OPTIONAL and item.state is State.MISSING:
        return f"{WORDS[item.record]} not used (optional, {item.asked})"
    return f"{WORDS[item.record]} {item.state.value}" + (f" ({item.detail})" if item.detail else "")
