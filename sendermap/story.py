"""The story: one paragraph, written by rules, that a reader who runs a company reads above the map.

Pure: it reads a finished SenderMap and nothing else. At most five sentences, in a fixed order,
each built only from objects in the map and left out when they are absent: the risks, who
receives the mail, the senders by category, account traces and report addresses, and what was not
checked. Every number is counted in the function that writes it. Nothing is said that the map's
findings, services, setups and gaps do not already show: no adjectives, no advice.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from .model import Denial, Gap, GapKind, Kind, SenderMap, Service, Severity, State, Tier
from .sources.ct import CRT_SH
from .sources.mx import NULL_MX
from .sources.spf_checks import EVALUATION

_NUMBERS = (
    *("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"),
    *("eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen"),
    *("eighteen", "nineteen", "twenty"),
)
GATEWAY = "Security gateway"
WEBSITE = "the website"
# How a Likely service is known, by the kind of the claim that decided it.
LIKELY_FROM = {
    Kind.DKIM_NAME: "from a DKIM key name alone",
    Kind.WEBSITE: "from a script or stylesheet the website loads",
    Kind.WEBSITE_MENTION: "from a mention on the website",
    Kind.SUBPROCESSOR: "from a subprocessor list",
    Kind.CT_ADDRESS: "from an address in its network at a name in certificate logs",
}
# What a mailbox provider's DKIM setup item at the domain says about signing.
SIGNING = {
    State.PRESENT: "and has a DKIM key in place to sign it",
    State.MISSING: "and has no DKIM key in place to sign it",
    State.BROKEN: "and its only DKIM key is broken",
    State.NOT_CHECKED: "and whether it has a DKIM key could not be checked",
}


def write(result: SenderMap) -> str:
    """The paragraph: the sentences that have something to say, in order."""
    sentences = (risks, receivers, senders, traces, unchecked)
    return " ".join(s for build in sentences if (s := build(result)))


def number(n: int) -> str:
    """A count in words up to twenty, in digits past it."""
    return _NUMBERS[n] if n < len(_NUMBERS) else str(n)


def risks(result: SenderMap) -> str:
    """Every finding of severity risk, one clause each, in the map's order, by its own title."""
    found = [f.title for f in result.findings if f.severity is Severity.RISK]
    if not found:
        return ""
    count = len(found)
    clauses = "; ".join(_lower_the(title) for title in found)
    return f"The map shows {number(count)} risk{_s(count)}: {clauses}."


def receivers(result: SenderMap) -> str:
    """Who is in the domain's MX, and for a mailbox provider whether its DKIM setup at the domain
    shows a key; a security gateway stands in front and hides the mailbox provider from MX."""
    clauses: list[str] = []
    for service in _in_mx(result):
        if service.category == GATEWAY:
            clauses.append(
                f"{service.name} stands in front of the domain's mail as a security gateway, so "
                "the mailbox provider is not visible from MX"
            )
            continue
        signing = _signing(service, result.domain)
        clauses.append(
            f"{service.name} receives the domain's mail" + (f" {signing}" if signing else "")
        )
    return _sentence("; ".join(clauses))


def senders(result: SenderMap) -> str:
    """The configured senders by category, in the map's order, then the likely ones by how each
    is known. "Other" when the receivers sentence named services already."""
    if not result.senders and not result.unknowns:
        return nothing(result)
    other = " other" if _in_mx(result) else ""
    configured = [s for s in result.senders if s.tier is Tier.CONFIGURED]
    parts = [_configured(configured, other)] if configured else []
    if likely := [s for s in result.senders if s.tier is Tier.LIKELY]:
        parts.append(_likely(likely, other, after=bool(configured)))
    return _sentence("; ".join(parts))


def nothing(result: SenderMap) -> str:
    """With no sender and nothing unrecognised in the map, what was asked at the domain and
    came back empty, written only when the map records what was asked at the domain. A part
    whose kind has a gap is left to the Not checked sentence. The map keeps no SPF record, only
    what SPF names, so SPF is worded by that."""
    here = next((c for c in result.checked if c.where == result.domain), None)
    if here is None:  # nothing shows the domain was asked
        return ""
    kinds = {g.kind for g in result.gaps}
    parts: list[str] = []
    if GapKind.MX not in kinds:
        null = any(f.title == NULL_MX for f in result.findings)
        parts.append("a null MX that says it accepts no mail" if null else "no MX")
    if GapKind.SPF not in kinds:
        parts.append("no sender in SPF")
    if GapKind.DKIM not in kinds:
        if here.denial is Denial.WILDCARD:
            parts.append("a wildcard that answers every DKIM name")
        elif asked := len(here.dkim_selectors):
            parts.append(f"no DKIM key at the {number(asked)} names asked")
    if not parts:
        return ""
    return f"No sending service shows in DNS for {result.domain}: {_listed(parts)}."


def _configured(configured: Sequence[Service], other: str) -> str:
    count = len(configured)
    listed = ", ".join(
        f"{number(len(names))} {_category(category)} ({', '.join(names)})"
        for category, names in _grouped(configured, lambda s: s.category)
    )
    return f"{_services(count, other)} set up to send as the domain: {listed}"


def _likely(likely: Sequence[Service], other: str, *, after: bool) -> str:
    """'two more are likely from a DKIM key name alone (Customer.io, Mandrill)', or with several
    ways of knowing, each counted."""
    count = len(likely)
    groups = _grouped(likely, lambda s: LIKELY_FROM.get(s.decided_by.kind, "from other records"))
    if after:
        lead = f"{number(count)} more {_is(count)} likely"
    else:
        lead = f"{_services(count, other)} likely to send as the domain"
    if len(groups) == 1:
        how, names = groups[0]
        return f"{lead} {how} ({', '.join(names)})"
    counted = ", ".join(f"{number(len(names))} {how} ({', '.join(names)})" for how, names in groups)
    return f"{lead}: {counted}"


def _services(count: int, other: str) -> str:
    """'eleven other services are', 'one service is'."""
    return f"{number(count)}{other} service{_s(count)} {_is(count)}"


def _is(count: int) -> str:
    return "is" if count == 1 else "are"


def traces(result: SenderMap) -> str:
    """The services with an account and nothing set up to send, and where the reports go."""
    parts: list[str] = []
    if accounts := [s.name for s in result.senders if s.tier is Tier.ACCOUNT_ONLY]:
        count = len(accounts)
        verb = "shows" if count == 1 else "show"
        parts.append(
            f"{number(count)} service{_s(count)} {verb} an account and nothing set up to send "
            f"({', '.join(accounts)})"
        )
    for kind, what in ((Kind.DMARC_REPORTS, "DMARC"), (Kind.TLSRPT_REPORTS, "TLS")):
        if names := [s.name for s in result.services if any(c.kind is kind for c in s.claims)]:
            parts.append(f"{what} reports go to {_and(names)}")
    return _sentence("; ".join(parts))


def unchecked(result: SenderMap) -> str:
    """What was not checked, one clause per kind of gap in plain words, counted, the detail left
    to the Not checked section below the map: the website first, then the kinds in a fixed
    order, then the other checks turned off. Caps and failures of one kind fold into one clause.
    No URL, no raw gap text, and no flag but the one that turns a check on."""
    by_kind: dict[GapKind, list[Gap]] = {}
    for gap in result.gaps:
        by_kind.setdefault(gap.kind, []).append(gap)
    off = by_kind.pop(GapKind.OFF, [])
    website = _website(by_kind.pop(GapKind.WEBSITE, []), off=any(g.asked == WEBSITE for g in off))
    clauses = [website, *(CLAUSES[kind](gaps) for kind, gaps in _in_order(by_kind))]
    clauses += [_off(g) for g in off if g.asked != WEBSITE]
    return f"Not checked: {_listed(found)}." if (found := [c for c in clauses if c]) else ""


def _in_order(by_kind: dict[GapKind, list[Gap]]) -> list[tuple[GapKind, list[Gap]]]:
    return [(kind, by_kind[kind]) for kind in CLAUSES if kind in by_kind]


def _parts(gaps: Sequence[Gap]) -> tuple[list[Gap], int, bool]:
    """The caps; how many things failed, counted; and whether a check failed as a whole."""
    caps = [g for g in gaps if g.cap]
    failed = sum(g.count for g in gaps if not g.cap)
    whole = any(not g.cap and not g.count for g in gaps)
    return caps, failed, whole


def _by_cap(caps: Sequence[Gap]) -> list[tuple[int, list[Gap]]]:
    groups: dict[int, list[Gap]] = {}
    for gap in caps:
        groups.setdefault(gap.cap, []).append(gap)
    return list(groups.items())


def _website(gaps: Sequence[Gap], *, off: bool) -> str:
    return "the website (turned off)" if off else _page(gaps, "the website")


def _page(gaps: Sequence[Gap], noun: str = "the subprocessor page") -> str:
    caps, failed, whole = _parts(gaps)
    if whole or failed:
        return f"{noun} (could not be read)"
    if caps:
        return f"{noun} past its first {_amount(caps[0].cap)} bytes"
    return ""


def _dkim(gaps: Sequence[Gap]) -> str:
    """'DKIM selectors past the first 27 on five subdomains and one that could not be read'.
    The budget cap applies on sending subdomains only."""
    caps, failed, _ = _parts(gaps)
    capped = " and ".join(
        f"past the first {number(cap)} on {number(len(group))} subdomain{_s(len(group))}"
        for cap, group in _by_cap(caps)
    )
    if not capped:
        return f"{number(failed)} DKIM selector{_s(failed)} that could not be read"
    return f"DKIM selectors {capped}" + (
        f" and {number(failed)} that could not be read" if failed else ""
    )


def _spf(gaps: Sequence[Gap]) -> str:
    evaluated = [g for g in gaps if g.asked.startswith(EVALUATION)]
    caps, failed, _ = _parts([g for g in gaps if g not in evaluated])
    parts = (
        [f"{number(failed)} SPF record{_s(failed)} whose lookup{_s(failed)} failed"]
        if failed
        else []
    )
    for cap, group in _by_cap(caps):
        deep = sum(g.count for g in group)
        parts.append(f"{number(deep)} SPF include{_s(deep)} more than {number(cap)} levels deep")
    return " and ".join(parts + _evaluation(evaluated))


def _evaluation(gaps: Sequence[Gap]) -> list[str]:
    """The vendors whose SPF evaluation ended in an error, and those past the budget."""
    caps, errors, _ = _parts(gaps)
    parts = [f"SPF evaluation for {number(errors)} vendor{_s(errors)} (an error)"] if errors else []
    if left := sum(g.count for g in caps):
        budget = _amount(caps[0].cap)
        parts.append(
            f"SPF evaluation for {number(left)} vendor{_s(left)} past its {budget} lookups"
        )
    return parts


def _mx(gaps: Sequence[Gap]) -> str:
    _, failed, whole = _parts(gaps)
    if whole:
        return "MX (could not be read)"
    return f"MX at {number(failed)} name{_s(failed)} whose lookup{_s(failed)} failed"


def _networks(gaps: Sequence[Gap]) -> str:
    """'network owners for 12 of 36 ranges', summed over the names with a cap."""
    caps, failed, _ = _parts(gaps)
    if not caps:
        return f"network owners for {number(failed)} range{_s(failed)} whose lookups failed"
    left = sum(g.count for g in caps)
    total = sum(g.count + g.cap for g in caps)
    at = f" at {number(len(caps))} names" if len(caps) > 1 else ""
    clause = f"network owners for {_of(left, total)} ranges{at}"
    return clause + (f" and for {number(failed)} whose lookups failed" if failed else "")


def _published(gaps: Sequence[Gap]) -> str:
    """The ranges other services publish in their own SPF: about the vendor data, not the
    domain, and it would name a service the map may not have found, so they are counted."""
    services = len(dict.fromkeys(g.asked for g in gaps))
    why = []
    for cap, group in _by_cap([g for g in gaps if g.cap]):
        count = len(dict.fromkeys(g.asked for g in group))
        why.append((count, f"past {number(cap)} include levels"))
    if failed := len(dict.fromkeys(g.asked for g in gaps if not g.cap)):
        why.append((failed, "lookups failed"))
    reasons = (
        why[0][1]
        if len(why) == 1
        else " and ".join(f"{reason} for {number(count)}" for count, reason in why)
    )
    one = services == 1
    return (
        f"the IP ranges {number(services)} service{_s(services)} publish{'es' if one else ''} "
        f"in {'its' if one else 'their'} own SPF ({reasons})"
    )


def _subdomains(gaps: Sequence[Gap]) -> str:
    caps, failed, whole = _parts(gaps)
    if whole:
        return "sending subdomains (could not be read)"
    parts = [f"{number(failed)} subdomain{_s(failed)} whose lookups failed"] if failed else []
    for cap, group in _by_cap(caps):
        more = sum(g.count for g in group)
        parts.append(f"sending subdomains past the first {number(cap)} ({number(more)} more)")
    return " and ".join(parts)


def _certificate_logs(gaps: Sequence[Gap]) -> str:
    caps, failed, _ = _parts(gaps)
    logs = sum(not g.cap and not g.count for g in gaps)
    parts = [f"{number(logs)} certificate log{_s(logs)} that could not be read"] if logs else []
    if failed:
        parts.append(
            f"{number(failed)} name{_s(failed)} from certificate logs whose lookups failed"
        )
    if left := sum(g.count for g in caps):
        parts.append(f"{number(left)} name{_s(left)} from certificate logs left out by a limit")
    return " and ".join(parts)


def _labels(gaps: Sequence[Gap]) -> str:
    _, failed, whole = _parts(gaps)
    if whole:
        return "bounce and tracking CNAMEs (could not be read)"
    return (
        f"bounce and tracking CNAMEs at {number(failed)} name{_s(failed)} whose "
        f"lookup{_s(failed)} failed"
    )


def _reports(gaps: Sequence[Gap]) -> str:
    _, failed, whole = _parts(gaps)
    if whole:
        return "report addresses (could not be read)"
    return f"report addresses at {number(failed)} name{_s(failed)} whose lookup{_s(failed)} failed"


def _tokens(gaps: Sequence[Gap]) -> str:
    return "verification tokens (could not be read)"


def _mta_sts(gaps: Sequence[Gap]) -> str:
    return "the MTA-STS policy (could not be read)"


def _other(gaps: Sequence[Gap]) -> str:
    return f"{number(len(gaps))} other check{_s(len(gaps))} (could not be read)"


def _off(gap: Gap) -> str:
    """A check the caller turned off, by what it is."""
    if gap.asked.startswith(f"certificate transparency, {CRT_SH.name}:"):
        return f"the {CRT_SH.name} certificate log (read only with --ct)"
    if gap.asked.startswith("MTA-STS policy"):
        return "the MTA-STS policy (turned off with the website and subdomains)"
    if gap.asked == "sending subdomains":
        return "sending subdomains (turned off)"
    return "one more check (turned off)"


# One clause per kind, in this order after the website.
CLAUSES: dict[GapKind, Callable[[Sequence[Gap]], str]] = {
    GapKind.PAGE: _page,
    GapKind.DKIM: _dkim,
    GapKind.NETWORKS: _networks,
    GapKind.SUBDOMAINS: _subdomains,
    GapKind.SPF: _spf,
    GapKind.MX: _mx,
    GapKind.PUBLISHED_RANGES: _published,
    GapKind.LABELS: _labels,
    GapKind.REPORTS: _reports,
    GapKind.TOKENS: _tokens,
    GapKind.MTA_STS: _mta_sts,
    GapKind.CERTIFICATE_LOG: _certificate_logs,
    GapKind.OTHER: _other,
}


def _in_mx(result: SenderMap) -> list[Service]:
    """The services in the domain's own MX, in the map's order."""
    return [
        s
        for s in result.services
        if any(c.kind is Kind.MX and c.where == result.domain for c in s.claims)
    ]


def _signing(service: Service, domain: str) -> str:
    for setup in service.setups:
        if setup.where != domain:
            continue
        for item in setup.items:
            if item.record == "dkim" and item.state in SIGNING:
                return SIGNING[item.state]
    return ""


def _grouped(
    services: Sequence[Service], key: Callable[[Service], str]
) -> list[tuple[str, list[str]]]:
    """Names grouped by key, groups in the order their first service stands in the map."""
    groups: dict[str, list[str]] = {}
    for service in services:
        groups.setdefault(key(service), []).append(service.name)
    return list(groups.items())


def _category(category: str) -> str:
    """A category as it reads mid sentence: "transactional", "support and CRM", "DMARC
    reporting"."""
    return category if category[1:2].isupper() else category[:1].lower() + category[1:]


def _lower_the(title: str) -> str:
    return "the" + title[3:] if title.startswith("The ") else title


def _and(names: Sequence[str]) -> str:
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def _listed(clauses: Sequence[str]) -> str:
    """'a', 'a and b', 'a, b, and c'."""
    return _and(clauses) if len(clauses) < 3 else f"{', '.join(clauses[:-1])}, and {clauses[-1]}"


def _of(part: int, whole: int) -> str:
    """'five of twelve', '12 of 36': both in words or both in digits."""
    if whole < len(_NUMBERS):
        return f"{number(part)} of {number(whole)}"
    return f"{part} of {whole}"


def _amount(n: int) -> str:
    """A cap in words: 'two million', or the number."""
    return (
        f"{number(n // 1_000_000)} million" if n >= 1_000_000 and not n % 1_000_000 else number(n)
    )


def _s(count: int) -> str:
    return "" if count == 1 else "s"


def _sentence(text: str) -> str:
    return f"{text[:1].upper()}{text[1:]}." if text else ""
