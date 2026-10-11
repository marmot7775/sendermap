"""Record a domain into the golden corpus, or rebuild a case's expected map offline.

    python tools/record_corpus.py DOMAIN [--web]
    python tools/record_corpus.py DOMAIN --update
    python tools/record_corpus.py --update

The first form maps DOMAIN live through the recorders, with checked_at fixed to the moment of
recording, CT off, and the website off unless --web is given, and writes
tests/corpus/<domain>/: dns.json (every DNS question and answer), http.json (every page
requested: the MTA-STS policy, the certificate log the subdomain search reads and, with --web,
the homepage), case.json (checked_at and the options) and expected.json, the map's JSON without
run.elapsed and run.lookups. expected.json is made by replaying the files just written, and the
tool fails if the replay differs from the live map, so a case that is saved replays.

--update rebuilds expected.json from the recorded answers without the network, for one case or
every case: for when a code change rightly changes the map. The diff it causes is the review.
"""

from __future__ import annotations

import argparse
import asyncio
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


async def record(domain: str, *, use_web: bool) -> Path:
    case = Case(
        clean_domain(domain), datetime.now(UTC).replace(microsecond=0), use_web, use_subdomains=True
    )
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
    directory = CORPUS / case.domain
    directory.mkdir(parents=True, exist_ok=True)
    resolver.save(directory / "dns.json")
    pages = directory / "http.json"
    if transport.responses:
        transport.save(pages)
    else:
        pages.unlink(missing_ok=True)
    _write_json(directory / "case.json", case.to_dict())
    replayed = await update(directory)
    if replayed != comparable(live):
        raise SystemExit(f"{case.domain}: the replay differs from the live map; not deterministic")
    return directory


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
    args = parser.parse_args(argv)
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
