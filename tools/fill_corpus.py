"""Answer, live, the questions a corpus case now asks that its recording does not hold.

A new SPF include or selector makes every map ask a few more questions, so the corpus test fails
with "the code asked what the recording does not hold". This replays each case, asks each missed
question once through the case's own resolver (Google or Cloudflare DNS over HTTPS), adds the
answers to dns.json and replays again until nothing is missed. Existing answers are never changed.

    python tools/fill_corpus.py            # every case
    python tools/fill_corpus.py casper.com # one case

Then run the tests: if expected.json changed meaning, `python tools/record_corpus.py --update`.
"""

import asyncio
import contextlib
import sys
from pathlib import Path

import httpx

from sendermap import map_domain
from sendermap.dns import DohResolver, doh_client
from sendermap.testing import (
    Case,
    ReplayResolver,
    ReplayTransport,
    UnrecordedError,
    _answer_row,
    _dump,
    _load,
)

CORPUS = Path(__file__).resolve().parent.parent / "tests" / "corpus"
ENDPOINTS = {name: url for url, name in DohResolver.NAMES.items()}


async def fill(directory: Path) -> int:
    case = Case.load(directory)
    endpoint = ENDPOINTS.get(case.resolver)
    if endpoint is None:
        raise SystemExit(f"{directory.name}: cannot fill a case recorded with {case.resolver!r}")
    path = directory / "dns.json"
    added = 0
    async with doh_client() as client:
        live = DohResolver(client, endpoint)
        for _ in range(10):  # each round's answers can lead to further questions
            missed = await _missed(directory, case)
            if not missed:
                return added
            answers = await asyncio.gather(*(live.query(n, t) for n, t in missed))
            rows = _load(path) + [_answer_row(a) for a in answers]
            rows.sort(key=lambda r: (r["name"].lower().rstrip("."), r["rtype"].upper()))
            _dump(path, rows)
            added += len(answers)
    raise SystemExit(f"{directory.name}: still missing answers after 10 rounds")


async def _missed(directory: Path, case: Case) -> list[tuple[str, str]]:
    """The questions a replay asked that dns.json lacks. Some sources let the first miss end the
    map, so the map runs here with the error caught, and the next round finds the rest."""
    resolver = ReplayResolver(directory / "dns.json", case.resolver)
    pages = directory / "http.json"
    transport = ReplayTransport(pages) if pages.exists() else ReplayTransport.empty()
    async with httpx.AsyncClient(transport=transport) as http:
        with contextlib.suppress(UnrecordedError):
            await map_domain(
                case.domain,
                checked_at=case.checked_at,
                resolver=resolver,
                http=http,
                use_web=case.use_web,
                use_subdomains=case.use_subdomains,
                use_ct=False,
            )
    if transport.missed:
        raise SystemExit(f"{directory.name}: missed pages cannot be filled here")
    return sorted(set(resolver.missed))


async def main(names: list[str]) -> None:
    cases = [CORPUS / n for n in names] or sorted(p.parent for p in CORPUS.glob("*/case.json"))
    for directory in cases:
        print(f"{directory.name}: {await fill(directory)} answers added")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
