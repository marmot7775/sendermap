"""The story: one paragraph, written by rules, that a reader who runs a company reads above the map.

Pure: it reads a finished SenderMap and nothing else. At most five sentences, in a fixed order,
each built only from objects in the map and left out when they are absent: the risks, who
receives the mail, the senders by category, account traces and report addresses, and what was not
checked. Every number is counted in the function that writes it. Nothing is said that the map's
findings, services, setups and gaps do not already show: no adjectives, no advice.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from .model import Gap, Kind, SenderMap, Service, Severity, State, Tier
from .sources.networks import PUBLISHED

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
    other = " other" if _in_mx(result) else ""
    configured = [s for s in result.senders if s.tier is Tier.CONFIGURED]
    parts = [_configured(configured, other)] if configured else []
    if likely := [s for s in result.senders if s.tier is Tier.LIKELY]:
        parts.append(_likely(likely, other, after=bool(configured)))
    return _sentence("; ".join(parts))


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
    """Every gap, one clause each in the map's order, the website first when it was not read.
    A gap in reading another service's own SPF for its published ranges is about the vendor
    data, not the domain, and names a service the map may not have found, so those are counted
    instead, one clause per reason."""
    gaps = sorted(result.gaps, key=lambda g: g.asked != WEBSITE)
    clauses = [f"{g.asked} ({g.happened})" for g in gaps if not g.asked.startswith(PUBLISHED)]
    for why, count in _published(gaps).items():
        clauses.append(
            f"the IP ranges {number(count)} service{_s(count)} publish{'es' if count == 1 else ''} "
            f"in {'its' if count == 1 else 'their'} own SPF ({why})"
        )
    return f"Not checked: {'; '.join(clauses)}." if clauses else ""


def _published(gaps: Sequence[Gap]) -> dict[str, int]:
    """How many published range gaps there are for each reason, in the map's order."""
    counts: dict[str, int] = {}
    for gap in gaps:
        if gap.asked.startswith(PUBLISHED):
            counts[gap.happened] = counts.get(gap.happened, 0) + 1
    return counts


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


def _s(count: int) -> str:
    return "" if count == 1 else "s"


def _sentence(text: str) -> str:
    return f"{text[:1].upper()}{text[1:]}." if text else ""
