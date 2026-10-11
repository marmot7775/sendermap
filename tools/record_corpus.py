"""Record a domain into the golden corpus, or rebuild a case's expected map offline.

    python tools/record_corpus.py DOMAIN [--web]
    python tools/record_corpus.py DOMAIN --update
    python tools/record_corpus.py --update
    python tools/record_corpus.py DOMAIN --recheck DIR

The first form maps DOMAIN live through the recorders, with checked_at fixed to the moment of
recording, CT off, and the website off unless --web is given, and writes
tests/corpus/<domain>/: dns.json (every DNS question and answer), http.json (every page
requested: the MTA-STS policy, the certificate log the subdomain search reads and, with --web,
the homepage), case.json (checked_at and the options) and expected.json, the map's JSON without
run.elapsed and run.lookups. expected.json is made by replaying the files just written, and the
tool fails if the replay differs from the live map, so a case that is saved replays.

--update rebuilds expected.json from the recorded answers without the network, for one case or
every case: for when a code change rightly changes the map. The diff it causes is the review.

--recheck maps a recorded case live again, with its own options and a fresh checked_at, records
into DIR/<domain>/ and prints, as markdown, how that map differs from expected.json, leaving out
checked_at and the order of lists. It writes nothing under tests/corpus and exits 0 on drift:
the world changing is not a bug. A drifted case is re-recorded by hand with the first form,
after reading the diff.
"""

from __future__ import annotations

import argparse
import asyncio
import difflib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from sendermap import map_domain
from sendermap.dns import SystemResolver
from sendermap.engine import clean_domain
from sendermap.testing import (
    Case,
    RecordingResolver,
    RecordingTransport,
    comparable,
    replay,
)

CORPUS = Path(__file__).resolve().parent.parent / "tests" / "corpus"


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


async def _map_live(case: Case, directory: Path) -> dict[str, Any]:
    """Map the case's domain live through the recorders and save what they kept in directory."""
    resolver = RecordingResolver(SystemResolver())
    transport = RecordingTransport()
    async with httpx.AsyncClient(transport=transport) as http:
        live = await map_domain(
            case.domain,
            checked_at=case.checked_at,
            resolver=resolver,
            http=http,
            use_web=case.use_web,
            use_subdomains=case.use_subdomains,
            use_ct=False,
        )
    directory.mkdir(parents=True, exist_ok=True)
    resolver.save(directory / "dns.json")
    pages = directory / "http.json"
    if transport.responses:
        transport.save(pages)
    else:
        pages.unlink(missing_ok=True)
    _write_json(directory / "case.json", case.to_dict())
    return comparable(live)


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


async def record(domain: str, *, use_web: bool) -> Path:
    case = Case(clean_domain(domain), _now(), use_web, use_subdomains=True)
    directory = CORPUS / case.domain
    live = await _map_live(case, directory)
    replayed = await update(directory)
    if replayed != live:
        raise SystemExit(f"{case.domain}: the replay differs from the live map; not deterministic")
    return directory


def _canonical(data: Any) -> Any:
    """data without checked_at at any depth and with every list sorted: a resolver may hand back
    an RRset in any order, and the map keeps the order it was given, so order is not drift."""
    if isinstance(data, dict):
        return {k: _canonical(v) for k, v in data.items() if k != "checked_at"}
    if isinstance(data, list | tuple):
        return sorted((_canonical(v) for v in data), key=lambda v: json.dumps(v, sort_keys=True))
    return data


def drift(expected: dict[str, Any], live: dict[str, Any]) -> list[str]:
    """The unified diff from expected to live, both without checked_at and with lists sorted;
    empty when they agree."""
    before, after = (
        json.dumps(_canonical(m), indent=1, ensure_ascii=False).splitlines()
        for m in (expected, live)
    )
    return list(difflib.unified_diff(before, after, "expected.json", "live", lineterm=""))


async def recheck(domain: str, out: Path) -> str:
    """Map a recorded case live into out/<domain>/; return the drift report as markdown."""
    recorded = Case.load(CORPUS / clean_domain(domain))
    case = Case(recorded.domain, _now(), recorded.use_web, recorded.use_subdomains)
    live = await _map_live(case, out / case.domain)
    expected = json.loads((CORPUS / case.domain / "expected.json").read_text(encoding="utf-8"))
    diff = drift(expected, live)
    if not diff:
        return f"### {case.domain}\n\nNo drift: the live map is the recorded one.\n"
    body = "\n".join(diff)
    return f"### {case.domain}\n\nDrifted ({len(diff)} diff lines):\n\n```diff\n{body}\n```\n"


async def update(directory: Path) -> dict[str, Any]:
    """Rebuild expected.json from the recorded files; return what was written."""
    replayed = await replay(directory)
    if replayed.missed:
        missed = "\n  ".join(replayed.missed)
        raise SystemExit(f"{directory.name}: asked what was not recorded:\n  {missed}")
    expected = comparable(replayed.map)
    _write_json(directory / "expected.json", expected)
    return expected


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("domain", nargs="?", help="the domain to record or update")
    parser.add_argument("--web", action="store_true", help="read the homepage too")
    parser.add_argument(
        "--update", action="store_true", help="rebuild expected.json offline, for one or all"
    )
    parser.add_argument(
        "--recheck", type=Path, metavar="DIR", help="map a case live into DIR and print the drift"
    )
    args = parser.parse_args(argv)
    if args.recheck:
        if not args.domain:
            parser.error("--recheck needs the domain of a recorded case")
        print(await recheck(args.domain, args.recheck))
        return 0
    if args.update:
        cases = [CORPUS / clean_domain(args.domain)] if args.domain else _cases()
        for directory in cases:
            await update(directory)
            print(f"updated {directory.name}")
        return 0
    if not args.domain:
        parser.error("give a domain to record, or --update")
    print(f"recorded {await record(args.domain, use_web=args.web)}")
    return 0


def _cases() -> list[Path]:
    return sorted(p for p in CORPUS.iterdir() if (p / "case.json").exists())


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
