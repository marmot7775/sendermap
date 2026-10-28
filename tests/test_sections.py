"""One list of sections for every view: the text, HTML and Markdown renderers each walk
render.view.SECTIONS and take every section name from it, so they show the same sections under
the same names in the same order, and a renamed section changes in all three or none."""

import io
import re
from pathlib import Path

import pytest
from rich.console import Console
from test_view import CASES, mapped

from sendermap.model import SenderMap
from sendermap.render import html, markdown, text
from sendermap.render.view import SECTIONS

NAMES = [name for _, name in SECTIONS]
# A section name is the only unindented line in the terminal view but the question on top.
_TEXT = re.compile(r"^([A-Z][^?\n]*?) *$", re.M)
_MARKDOWN = re.compile(r"^## (.+)$", re.M)
_HTML = re.compile(r'<h3 class="section-title">([^<]*)</h3>')
_TABLE_WIDTH = 70


def text_names(result: SenderMap, *, evidence: bool) -> list[str]:
    out = io.StringIO()
    text.render(result, Console(file=out, width=100, color_system=None), evidence=evidence)
    return _TEXT.findall(out.getvalue())


def markdown_names(result: SenderMap, *, evidence: bool) -> list[str]:
    return _MARKDOWN.findall(markdown.render(result, evidence=evidence))


def test_each_renderer_has_a_part_for_every_section_and_no_other() -> None:
    keys = [key for key, _ in SECTIONS]
    for renderer in (text, html, markdown):
        assert list(renderer._SECTIONS) == keys, renderer.__name__


def test_the_names_are_distinct() -> None:
    assert len({name.upper() for name in NAMES}) == len(NAMES)


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_the_three_renderers_show_the_same_sections_in_order(case: Path) -> None:
    result = await mapped(case)
    page = _HTML.findall(html.html(result))
    full = markdown_names(result, evidence=True)
    assert page == [name for name in NAMES if name in page]
    assert full == page
    assert text_names(result, evidence=True) == page
    brief = markdown_names(result, evidence=False)
    assert text_names(result, evidence=False) == brief


async def test_the_corpus_shows_most_sections() -> None:
    """The order test above means something only if the corpus reaches most sections."""
    shown = {name for case in CASES for name in markdown_names(await mapped(case), evidence=True)}
    assert len(shown) >= len(NAMES) - 2


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_the_markdown_has_no_table_wider_than_a_plain_email(case: Path) -> None:
    result = await mapped(case)
    for evidence in (False, True):
        page = markdown.render(result, evidence=evidence)
        rows = [line for line in page.splitlines() if line.startswith("|")]
        assert all(len(row) <= _TABLE_WIDTH for row in rows)
