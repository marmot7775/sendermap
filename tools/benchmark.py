"""Map a fixed list of domains live and measure how much of what they publish Sendermap names.

    python tools/benchmark.py [--domains FILE] [--limit N] [--jobs N] [--out DIR]
    python tools/benchmark.py --compare OLD.json [NEW.json]
    python tools/benchmark.py --report RUN.json

The first form maps every domain in FILE (default data/benchmark_domains.txt) with the CLI's
defaults (website and sending subdomains on, certificate logs off), writes the run to
DIR/<date>-<version>.json (default benchmark/runs) and prints its summary as markdown. A domain
that fails to map is counted, with its error, and the run goes on.

The headline is the shared named unknowns: an SPF include, a mail server, a CNAME, a DKIM
selector or a report address that is clearly a sender, matches no service in the catalog, and
shows at two domains or more (a DKIM selector is listed but not counted: its name says nothing
of who signs). Each group is a vendors.json entry waiting to be written, so the
ranked list is the work list, and its count going down from one release to the next is the
measure. A group only one domain publishes is most often that company's own system. Unknown IP
addresses are counted apart: most are a company's own servers, which no entry should name.

--compare prints how a newer run differs from an older one (the newest run in DIR when NEW is
left out): every number, and the services each domain gained or lost. The two runs ask live DNS
at different moments, so some of the difference is the world changing; a service lost with no
catalog change is that, or a bug worth a look.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from sendermap import __version__, map_domain
from sendermap.model import SenderMap

ROOT = Path(__file__).resolve().parent.parent
DOMAINS = ROOT / "data" / "benchmark_domains.txt"
RUNS = ROOT / "benchmark" / "runs"
# Unknowns that are addresses, not names: most are the domain's own servers.
ADDRESS_KINDS = frozenset({"IP address in SPF", "IP range in SPF"})
# Second-level labels under which a country's registrable names sit (example.co.uk).
SHORT_SECOND_LEVEL = frozenset({"co", "com", "net", "org", "ac", "gov", "edu", "ne", "or"})
TOP = 30
UNANNOUNCED = "no one network announces it"
# A selector name says nothing of who signs: "mail" at two domains is two companies' own keys.
NOT_SHARED = frozenset({"DKIM key"})


@dataclass(frozen=True, slots=True)
class Lead:
    """One unknown shared across domains: what it is, the zone or selector it groups under,
    how many domains publish it, and one value as published."""

    what: str
    key: str
    domains: int
    example: str


def read_domains(path: Path) -> list[str]:
    """The domains in a list file, one per line, without comments, blanks or repeats."""
    lines = (line.split("#", 1)[0].strip().lower() for line in path.read_text().splitlines())
    return list(dict.fromkeys(line for line in lines if line))


def zone(host: str) -> str:
    """The registrable part of a host name, near enough to group one vendor's names by:
    the last two labels, or three under a short country second level (example.co.uk)."""
    labels = host.lower().rstrip(".").split(".")
    keep = 3 if len(labels) > 2 and labels[-2] in SHORT_SECOND_LEVEL else 2
    return ".".join(labels[-keep:])


def kind(what: str) -> str:
    """An unknown's kind without the label it was seen at: every CNAME is one kind."""
    return "CNAME" if what.startswith("CNAME at ") else what


def network(value: str) -> str:
    """The network an unknown address sits in, from the value's parenthesis, as
    "AS14340, SALESFORCE - Salesforce.com, Inc., US"; the value itself when it names none."""
    start = value.find(" (")
    return value[start + 2 : -1] if start != -1 and value.endswith(")") else value


def group_key(what: str, value: str) -> str:
    """What one unknown is grouped under across domains: a DKIM selector by its name, an
    address by its network, any host name by its zone."""
    if what == "DKIM key":
        return value.split(maxsplit=1)[0].lower()  # "selector1 via <target>": selector1
    if what in ADDRESS_KINDS:
        owner = network(value)
        # An address no network announces groups by itself, not with every other such address.
        return value.split(maxsplit=1)[0] if owner.startswith(UNANNOUNCED) else owner
    return zone(value)


def record(m: SenderMap) -> dict[str, Any]:
    """The parts of one map a benchmark keeps: small enough to commit a run of hundreds."""
    gaps = Counter(g.kind.value for g in m.gaps)
    own = m.domain
    return {
        "senders": {s.name: s.tier.value if s.tier else None for s in m.senders},
        "reporting": sorted(s.name for s in m.reporting),
        "unknowns": [
            {"what": u.what, "value": u.value}
            for u in m.unknowns
            # A host under the domain itself is its own server, not a vendor to name.
            if not (u.value == own or u.value.endswith("." + own))
        ],
        "gaps": dict(sorted(gaps.items())),
        "lookups": m.run.lookups,
        "elapsed": round(m.run.elapsed, 2),
        "resolver": m.run.resolver,
    }


async def run(domains: list[str], jobs: int) -> dict[str, Any]:
    """Map every domain, `jobs` at a time, sharing one HTTP client."""
    checked_at = datetime.now(UTC)
    gate = asyncio.Semaphore(jobs)
    results: dict[str, Any] = {}
    async with httpx.AsyncClient(http2=False, timeout=15) as http:

        async def one(domain: str) -> None:
            async with gate:
                try:
                    m = await map_domain(domain, checked_at=checked_at, http=http)
                    results[domain] = record(m)
                except Exception as error:  # a failed domain is a result
                    results[domain] = {"error": f"{type(error).__name__}: {error}"}
                print(f"  {len(results)}/{len(domains)} {domain}", file=sys.stderr)

        await asyncio.gather(*(one(d) for d in domains))
    return {
        "version": __version__,
        "checked_at": checked_at.isoformat(),
        "options": {"web": True, "subdomains": True, "ct": False},
        "domains": {d: results[d] for d in domains},
    }


def leads(domains: dict[str, Any], named: bool) -> list[Lead]:
    """The unknowns grouped across domains, most widely published first; `named` picks the
    host names and selectors, otherwise the addresses."""
    seen: dict[tuple[str, str], set[str]] = defaultdict(set)
    example: dict[tuple[str, str], str] = {}
    for domain, result in domains.items():
        for u in result.get("unknowns", ()):
            if (u["what"] in ADDRESS_KINDS) == named:
                continue
            key = (kind(u["what"]), group_key(u["what"], u["value"]))
            seen[key].add(domain)
            example.setdefault(key, u["value"])
    ranked = sorted(seen.items(), key=lambda item: (-len(item[1]), item[0]))
    return [Lead(what, key, len(ds), example[(what, key)]) for (what, key), ds in ranked]


def numbers(data: dict[str, Any]) -> dict[str, float]:
    """The run's measures, each a plain number so two runs subtract."""
    mapped = {d: r for d, r in data["domains"].items() if "error" not in r}
    senders = [len(r["senders"]) for r in mapped.values()]
    named = [u for r in mapped.values() for u in r["unknowns"] if u["what"] not in ADDRESS_KINDS]
    clean = sum(
        1 for r in mapped.values() if all(u["what"] in ADDRESS_KINDS for u in r["unknowns"])
    )
    elapsed = sorted(r["elapsed"] for r in mapped.values())
    count = len(mapped) or 1
    return {
        "domains": len(data["domains"]),
        "mapped": len(mapped),
        "failed": len(data["domains"]) - len(mapped),
        "senders": sum(senders),
        "no sender found": sum(1 for n in senders if n == 0),
        "named unknowns": len(named),
        "named unknown groups": len(groups := leads(mapped, named=True)),
        # Published by two domains or more: a vendor, where most one-offs are a company's own.
        "shared named groups": sum(
            1 for lead in groups if lead.domains > 1 and lead.what not in NOT_SHARED
        ),
        "domains fully named": clean,
        "fully named %": round(100 * clean / count, 1),
        "address unknowns": sum(len(r["unknowns"]) for r in mapped.values()) - len(named),
        "gaps": sum(sum(r["gaps"].values()) for r in mapped.values()),
        "median lookups": statistics.median(r["lookups"] for r in mapped.values()) if mapped else 0,
        "median seconds": statistics.median(elapsed) if elapsed else 0,
        "p95 seconds": elapsed[int(0.95 * (len(elapsed) - 1))] if elapsed else 0,
    }


def _table(rows: Iterable[tuple[Any, ...]], head: tuple[str, ...]) -> list[str]:
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return lines


def report(data: dict[str, Any]) -> str:
    """One run as markdown: its numbers, then the named and address leads."""
    mapped = {d: r for d, r in data["domains"].items() if "error" not in r}
    out = [f"# Benchmark {data['version']}, {data['checked_at'][:10]}", ""]
    out += _table(numbers(data).items(), ("measure", "value"))
    for title, named in (("Named unknowns", True), ("Unknown address networks", False)):
        out += ["", f"## {title}, by domains publishing them", ""]
        rows = (
            (ld.domains, ld.what, f"`{ld.key}`", f"`{ld.example}`")
            for ld in leads(mapped, named)[:TOP]
        )
        out += _table(rows, ("domains", "kind", "groups as", "example"))
    failed = sorted((d, r["error"]) for d, r in data["domains"].items() if "error" in r)
    if failed:
        out += ["", "## Failed", ""] + [f"- {d}: {e}" for d, e in failed]
    return "\n".join(out) + "\n"


def compare(old: dict[str, Any], new: dict[str, Any]) -> str:
    """How `new` differs from `old`: every number, then each domain's services gained and lost."""
    a, b = numbers(old), numbers(new)
    out = [f"# Benchmark {old['version']} -> {new['version']}", ""]
    rows = ((k, a[k], b[k], round(b[k] - a[k], 2)) for k in a)
    out += _table(rows, ("measure", old["version"], new["version"], "change"))
    changes = []
    for domain in sorted(set(old["domains"]) & set(new["domains"])):
        before = set(old["domains"][domain].get("senders", ()))
        after = set(new["domains"][domain].get("senders", ()))
        if before != after:
            gained = ", ".join(sorted(after - before)) or "-"
            lost = ", ".join(sorted(before - after)) or "-"
            changes.append((domain, gained, lost))
    out += ["", "## Services gained and lost", ""]
    out += _table(changes, ("domain", "gained", "lost")) if changes else ["None."]
    return "\n".join(out) + "\n"


def _newest(directory: Path) -> Path:
    runs = sorted(directory.glob("*.json"))
    if not runs:
        raise SystemExit(f"no runs in {directory}")
    return runs[-1]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--domains", type=Path, default=DOMAINS)
    p.add_argument("--limit", type=int, default=0, help="map only the first N domains")
    p.add_argument("--jobs", type=int, default=6, help="domains mapped at once")
    p.add_argument("--out", type=Path, default=RUNS)
    p.add_argument("--compare", nargs="+", type=Path, metavar="RUN")
    p.add_argument("--report", type=Path, metavar="RUN")
    args = p.parse_args(argv)

    if args.report:
        print(report(json.loads(args.report.read_text())), end="")
        return 0
    if args.compare:
        old = args.compare[0]
        new = args.compare[1] if len(args.compare) > 1 else _newest(args.out)
        print(compare(json.loads(old.read_text()), json.loads(new.read_text())), end="")
        return 0

    domains = read_domains(args.domains)
    if args.limit:
        domains = domains[: args.limit]
    data = asyncio.run(run(domains, args.jobs))
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{data['checked_at'][:10]}-{data['version']}.json"
    path.write_text(
        json.dumps(data, separators=(",", ":")) + "\n"
    )  # one run per release: keep it small
    print(f"wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}", file=sys.stderr)
    print(report(data), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
