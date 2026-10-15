"""Check every proof in data/vendors.json against live DNS and the web.

For each proof, ask for its record once and report found, not found, or could not check, with
what is published there now. What counts as found depends on the kind of pattern:

- a DKIM selector: a TXT record holding a key (p=), directly or through a CNAME;
- an SPF include: one SPF record at the name, with an include or redirect to the pattern;
- an MX host: an MX record at the name whose host is the pattern or a name under it;
- a delegation: an NS record at the name itself, not reached through a CNAME, whose host is the
  pattern or a name under it;
- a DKIM, bounce, tracking or other CNAME: a CNAME chain from the name with a hop at or under the
  pattern (for other_cname, the pattern's target);
- a report address: a DMARC or TLS-RPT record at the name with a mailto: address at or under the
  pattern;
- a verification token: a TXT record at the name that the pattern matches, with a value after it;
- a network: an address of the name that, by Team Cymru's answers, the network announces, with
  every origin network of that address the vendor's, read by the map's own networks.owner and
  credited by its rule, so an address two networks announce counts the same in any order;
- a sending address: one SPF record at the name with an authorizing ip4 or ip6 range that holds
  the address (the service's own record publishing it), or an A or AAAA record at the name that
  is the address (a host of the service's that sends from it);
- a website host: the page at the URL loads a script or stylesheet from the pattern's host;
- a subprocessor name: the page at the URL has the name as a whole word in its text;
- a setup item: the vendor's documentation page at the URL contains every value the item names
  (an item that names none needs only the page).

Anything else at the name, such as a wildcard SPF record where a key should be, is not found. A
lookup or request that fails, or a page that answers with anything but 200, 404 or 410, is could
not check: it says nothing about the proof, so it is listed but never fails the run. Exits 1 if
any proof is not found.

Usage: python tools/verify_proofs.py [--json] [--doh]

--json prints one JSON object per proof, one per line, with vendor, field, pattern, domain,
record, expected, observed and status; the totals line goes to stderr. --doh asks Cloudflare's
DNS over HTTPS instead of the machine's resolver.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx

from sendermap import catalog
from sendermap.catalog import Pattern, SetupRule
from sendermap.dns import (
    Answer,
    DohResolver,
    Lookups,
    Resolver,
    Status,
    SystemResolver,
    doh_client,
    norm,
)
from sendermap.proofs import Proof
from sendermap.selectors import Rule
from sendermap.sources import Context, networks
from sendermap.sources.reports import report_domains
from sendermap.sources.spf import spf_records, terms
from sendermap.sources.web import _LOADED, USER_AGENT

FOUND = "found"
NOT_FOUND = "not found"
UNCHECKED = "could not check"

TIMEOUT = 3.0  # seconds per query
CONCURRENCY = 4
EXPECTED = {
    "selectors": "TXT record holding a DKIM key (p=)",
    "spf_includes": "SPF record with an include or redirect to {}",
    "published_spf": "SPF record with an include or redirect to {}",
    "mx": "MX record with a host at or under {}",
    "delegation_ns": "NS record at the name with a host at or under {}",
    "dkim_cname": "CNAME chain through a name at or under {}",
    "return_path": "CNAME chain through a name at or under {}",
    "tracking": "CNAME chain through a name at or under {}",
    "other_cname": "CNAME chain through a name at or under {}",
    "reporting": "report address at or under {}",
    "verification_txt": "TXT record matching {}",
    "networks": "an address announced by {}",
    "sending_ip": "an SPF range holding {} at the name, or the name's own address",
    "website": "a page that loads a script or stylesheet from {}",
    "subprocessor_names": "a page that names {}",
    "setup": "a documentation page that contains {}",  # with no values, the page alone
}


@dataclass(frozen=True, slots=True)
class Result:
    vendor: str
    field: str
    pattern: str
    domain: str
    record: str
    expected: str
    observed: str
    status: str


@dataclass(frozen=True, slots=True)
class Seen:
    """What one check saw: whether the record shows the pattern, and what is published there.
    `answered` is False when the lookup or request failed."""

    shows: bool
    observed: str
    answered: bool = True


Check = Callable[["Checker", str, str], Awaitable[Seen]]


class Checker:
    """Asks for proof records through one resolver and one HTTP client. `owners` says which
    vendor each network (ASN) belongs to, for the network proofs: they read an address's origins
    through the map's own Context, whose catalog credits networks by it."""

    def __init__(
        self, resolver: Resolver, http: httpx.AsyncClient, owners: Mapping[str, str] | None = None
    ) -> None:
        self.resolver, self.http = resolver, http
        loaded = catalog.load()
        credits = {asn.upper(): vendor for asn, vendor in (owners or {}).items()}
        self.ctx = Context(
            "", Lookups(resolver), replace(loaded, networks=credits), datetime.now(UTC)
        )

    async def query(self, name: str, rtype: str) -> Answer:
        return await self.resolver.query(name, rtype)


def _under(host: str, pattern: str) -> bool:
    host, pattern = norm(host), norm(pattern)
    return host == pattern or host.endswith("." + pattern)


def _seen(answer: Answer, shows: bool) -> Seen:
    return Seen(shows, _observed(answer), answer.answered)


async def _key(checker: Checker, record: str, _: str) -> Seen:
    answer = await checker.query(record, "TXT")
    return _seen(answer, any("p=" in r for r in answer.records))


async def _spf(checker: Checker, record: str, pattern: str) -> Seen:
    answer = await checker.query(record, "TXT")
    records = spf_records(answer)
    shows = len(records) == 1 and any(
        t.mechanism in ("include", "redirect") and _under(t.value, pattern)
        for t in terms(records[0])
    )
    return _seen(answer, shows)


async def _mx(checker: Checker, record: str, pattern: str) -> Seen:
    answer = await checker.query(record, "MX")
    return _seen(answer, any(_under(r.partition(" ")[2], pattern) for r in answer.records))


async def _ns(checker: Checker, record: str, pattern: str) -> Seen:
    """NS records reached through a CNAME are the target's, so they delegate nothing here."""
    answer = await checker.query(record, "NS")
    return _seen(answer, not answer.chain and any(_under(r, pattern) for r in answer.records))


async def _cname(checker: Checker, record: str, pattern: str) -> Seen:
    answer = await checker.query(record, "CNAME")
    return _seen(answer, any(_under(hop, pattern) for hop in answer.chain))


async def _reports(checker: Checker, record: str, pattern: str) -> Seen:
    answer = await checker.query(record, "TXT")
    tags = ("rua", "ruf") if record.startswith("_dmarc.") else ("rua",)
    hosts = [h for r in answer.records for h in report_domains(r, tags)]
    return _seen(answer, any(_under(h, pattern) for h in hosts))


async def _token(checker: Checker, record: str, pattern: str) -> Seen:
    answer = await checker.query(record, "TXT")
    rx = re.compile(pattern, re.IGNORECASE)
    texts = (r.strip().lower() for r in answer.records)
    return _seen(answer, any((m := rx.match(t)) and len(t[m.end() :].strip()) >= 4 for t in texts))


async def _network(checker: Checker, record: str, asn: str) -> Seen:
    """An address the network announces, credited as the map credits it: every origin network
    Team Cymru answers with must be the vendor's, whatever order the answers come in."""
    answer = await checker.query(record, "A")
    if not answer.ok:
        return _seen(answer, False)
    asn = asn.upper()
    vendor = checker.ctx.catalog.network(asn)
    announced: list[str] = []
    shows = False
    for ip in answer.records:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        owner = await networks.owner(checker.ctx, address)
        if owner is None:
            return Seen(False, f"{ip}: network lookup failed", False)
        if owner.asns:
            announced.append(f"{ip} {' and '.join(owner.asns)}")
        credited = networks.credited(checker.ctx, owner)
        shows |= asn in owner.asns and credited is not None and credited == vendor
    return Seen(shows, "; ".join(announced) or "no network announces its addresses")


async def _sending_ip(checker: Checker, record: str, address: str) -> Seen:
    """The service's own SPF record at the name publishes a range holding the address, or the
    name's own address is it. An outbound host may publish a HELO record of its own ("v=spf1 a
    -all"), so both are read."""
    ip = ipaddress.ip_address(address)
    answer = await checker.query(record, "TXT")
    records = spf_records(answer)
    if len(records) == 1 and any(
        t.authorizes and t.mechanism in ("ip4", "ip6") and _holds(t.value, ip)
        for t in terms(records[0])
    ):
        return _seen(answer, True)
    host = await checker.query(record, "A" if ip.version == 4 else "AAAA")
    if any(_holds(r, ip) for r in host.records):
        return _seen(host, True)
    # Neither shows it; a lookup that failed leaves the proof unchecked, not disproved.
    observed = f"TXT {_observed(answer)}; {host.rtype} {_observed(host)}"
    return Seen(False, observed, answer.answered and host.answered)


def _holds(cidr: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        return ip in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


async def _page(checker: Checker, url: str) -> httpx.Response | Seen:
    """The page at `url`, or what to report when it could not be read. A page that is gone is
    not found; any other refusal says nothing about the proof."""
    try:
        response = await checker.http.get(
            url, headers={"user-agent": USER_AGENT}, follow_redirects=True, timeout=20
        )
    except httpx.HTTPError as e:
        return Seen(False, f"request failed: {type(e).__name__}", False)
    if response.status_code != 200:
        return Seen(False, f"HTTP {response.status_code}", response.status_code in (404, 410))
    return response


async def _website(checker: Checker, url: str, pattern: str) -> Seen:
    page = await _page(checker, url)
    if isinstance(page, Seen):
        return page
    hosts = [urlsplit(urljoin(str(page.url), s)).hostname or "" for s in _LOADED.findall(page.text)]
    loads = [h for h in hosts if h and _under(h, pattern)]
    return Seen(bool(loads), f"loads {', '.join(dict.fromkeys(loads))}" if loads else "no load")


async def _named(checker: Checker, url: str, name: str) -> Seen:
    page = await _page(checker, url)
    if isinstance(page, Seen):
        return page
    text = re.sub(r"<[^>]+>", " ", page.text)
    shows = re.search(rf"\b{re.escape(name)}\b", text) is not None
    return Seen(shows, f"names {name}" if shows else f"does not name {name}")


async def _setup(checker: Checker, url: str, values: str) -> Seen:
    """The page contains every value, as written anywhere in it, ignoring case."""
    page = await _page(checker, url)
    if isinstance(page, Seen):
        return page
    text = page.text.lower()
    lacking = [v for v in values.split() if v.lower() not in text]
    if lacking:
        return Seen(False, f"does not contain {', '.join(lacking)}")
    return Seen(True, f"contains {', '.join(values.split())}" if values else "page read")


CHECKS: dict[str, Check] = {
    "selectors": _key,
    "spf_includes": _spf,
    "published_spf": _spf,
    "mx": _mx,
    "delegation_ns": _ns,
    "dkim_cname": _cname,
    "return_path": _cname,
    "tracking": _cname,
    "other_cname": _cname,
    "reporting": _reports,
    "verification_txt": _token,
    "networks": _network,
    "sending_ip": _sending_ip,
    "website": _website,
    "subprocessor_names": _named,
    "setup": _setup,
}


@dataclass(frozen=True, slots=True)
class Item:
    """One proof to check: whose, for which pattern, and the record it names."""

    vendor: str
    field: str
    pattern: str
    proof: Proof
    setup_record: str = ""  # for a setup item, the record it describes (spf, dkim and so on)

    @property
    def shown(self) -> str:
        """The pattern as listed: a selector's name is the first label of its record."""
        return self.proof.record.split(".", 1)[0] if self.field == "selectors" else self.pattern


def items(
    rules: tuple[Rule, ...], patterns: tuple[Pattern, ...], setups: tuple[SetupRule, ...] = ()
) -> list[Item]:
    """Every proof: the selector rules' first, then every other pattern's, in file order, then
    each setup item's, whose pattern is its values separated by spaces."""
    keys = [
        Item(rule.vendor, "selectors", ", ".join(rule.shape.expand()), proof)
        for rule in rules
        for proof in rule.proofs
    ]
    documented = [Item(s.vendor, "setup", " ".join(s.values), s.proof, s.record) for s in setups]
    return keys + [Item(p.vendor, p.field, p.value, p.proof) for p in patterns] + documented


async def check(checker: Checker, item: Item) -> tuple[Result, str]:
    """The result for one proof, and its line of text report."""
    seen = await CHECKS[item.field](checker, item.proof.record, item.pattern)
    status = FOUND if seen.shows else NOT_FOUND if seen.answered else UNCHECKED
    word = {FOUND: "found     ", NOT_FOUND: "not found ", UNCHECKED: "unchecked "}[status]
    field = f"{item.field} {item.setup_record}" if item.setup_record else item.field
    label = f"{item.vendor} {field} [{item.pattern}] {item.proof.record} ({item.proof.date})"
    result = Result(
        vendor=item.vendor,
        field=field,
        pattern=item.shown,
        domain=item.proof.domain,
        record=item.proof.record,
        expected=EXPECTED[item.field].format(item.pattern).strip(),
        observed=seen.observed,
        status=status,
    )
    return result, f"{word} {label}: {seen.observed}"


def _observed(answer: Answer) -> str:
    """The raw answer: its records, or NXDOMAIN, no data, or the failure."""
    via = f" (via {' -> '.join(answer.chain)})" if answer.chain else ""
    match answer.status:
        case Status.OK:
            return " | ".join(answer.records) + via
        case Status.NXDOMAIN:
            return "NXDOMAIN" + via
        case Status.NOANSWER:
            return "no data" + via
        case _:
            return "lookup failed"


async def verify(checker: Checker, todo: list[Item]) -> list[tuple[Result, str]]:
    """Check every proof, a few at a time."""
    limit = asyncio.Semaphore(CONCURRENCY)

    async def one(item: Item) -> tuple[Result, str]:
        async with limit:
            return await check(checker, item)

    return await asyncio.gather(*map(one, todo))


def totals(results: list[Result]) -> str:
    found = sum(r.status == FOUND for r in results)
    unchecked = sum(r.status == UNCHECKED for r in results)
    line = f"{found} of {len(results)} proofs found"
    return f"{line}, {unchecked} could not be checked" if unchecked else line


def load() -> list[Item]:
    """Every proof in the vendor data Sendermap ships."""
    loaded = catalog.load()
    setups = tuple(rule for rules in loaded.setups.values() for rule in rules)
    backed_only = [
        Item(loaded.backed_only_selectors[name], "selectors", name, proof)
        for name, proof in loaded.backed_only_proofs.items()
    ]
    return items(loaded.rules, loaded.patterns, setups) + backed_only


async def main(argv: list[str] | None = None, http: httpx.AsyncClient | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check every vendor proof against live DNS.")
    parser.add_argument("--json", action="store_true", help="print one JSON object per proof")
    parser.add_argument("--doh", action="store_true", help="look up DNS over HTTPS (Cloudflare)")
    args = parser.parse_args(argv)

    async with http or httpx.AsyncClient() as client, doh_client() as dns_http:
        todo = load()
        owners = {i.pattern: i.vendor for i in todo if i.field == "networks"}
        resolver: Resolver = DohResolver(dns_http) if args.doh else SystemResolver(timeout=TIMEOUT)
        checked = await verify(Checker(resolver, client, owners), todo)
    results = [result for result, _ in checked]
    for result, line in checked:
        print(json.dumps(asdict(result)) if args.json else line)
    print(totals(results), file=sys.stderr if args.json else sys.stdout)
    return 1 if any(r.status == NOT_FOUND for r in results) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
