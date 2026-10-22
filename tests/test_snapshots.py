"""Each corpus case's text and Markdown views, with evidence off and on, compared byte for byte
with tests/snapshots/<domain>/. The run's elapsed time is set to zero first.

When a view changes on purpose, run `SENDERMAP_UPDATE_SNAPSHOTS=1 pytest tests/test_snapshots.py`
and review the diff to tests/snapshots.
"""

import difflib
import io
import os
from dataclasses import replace
from pathlib import Path

import pytest
from rich.console import Console
from test_view import CASES, mapped

from sendermap.model import SenderMap
from sendermap.render import markdown, text

SNAPSHOTS = Path(__file__).parent / "snapshots"
VIEWS = ("text.txt", "text-evidence.txt", "markdown.md", "markdown-evidence.md")


def rendered(result: SenderMap, name: str) -> str:
    evidence = "evidence" in name
    if name.startswith("markdown"):
        return markdown.render(result, evidence=evidence)
    out = io.StringIO()
    text.render(result, Console(file=out, width=100, color_system=None), evidence=evidence)
    return out.getvalue()


@pytest.mark.parametrize("name", VIEWS)
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_a_view_matches_its_snapshot(case: Path, name: str) -> None:
    result = await mapped(case)
    result = replace(result, run=replace(result.run, elapsed=0.0))
    got = rendered(result, name)
    path = SNAPSHOTS / case.name / name
    if os.environ.get("SENDERMAP_UPDATE_SNAPSHOTS"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(got.encode())
    want = path.read_bytes().decode()
    if got != want:
        diff = difflib.unified_diff(
            want.splitlines(keepends=True),
            got.splitlines(keepends=True),
            fromfile=str(path.relative_to(SNAPSHOTS.parent)),
            tofile="rendered now",
        )
        pytest.fail("".join(diff), pytrace=False)
