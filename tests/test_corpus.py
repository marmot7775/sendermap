"""The golden corpus: every recorded domain, mapped again offline, gives the map it gave live.

A failure here means the code changed what a real domain's map says. If the change is right,
run `python tools/record_corpus.py --update` and review the diff to expected.json.
"""

import json
from pathlib import Path

import pytest

from sendermap.testing import comparable, replay

CORPUS = Path(__file__).parent / "corpus"
CASES = sorted(p for p in CORPUS.iterdir() if (p / "case.json").exists())


def test_there_are_cases_and_the_readme_names_each() -> None:
    readme = (CORPUS / "README.md").read_text()
    assert len(CASES) >= 5
    for case in CASES:
        assert f"`{case.name}`" in readme, f"tests/corpus/README.md does not name {case.name}"


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_a_recorded_domain_maps_as_it_did(case: Path) -> None:
    replayed = await replay(case)
    assert replayed.missed == [], "the code asked what the recording does not hold"
    expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    assert json.loads(json.dumps(comparable(replayed.map))) == expected
