"""The rules every view keeps: findings first, each thing said once, evidence rendered per kind,
lists counted unless asked for. They are checked on the View and on both views of every corpus
case."""

import io
import json
import re
from pathlib import Path

import pytest
from rich.console import Console

from sendermap.model import Gap, GapKind, SenderMap, State
from sendermap.render import markdown, text, view
from sendermap.render.view import ServiceView, View, grouped_gaps
from sendermap.testing import replay

CORPUS = Path(__file__).parent / "corpus"
CASES = sorted(p for p in CORPUS.iterdir() if (p / "case.json").exists())
_MAPS: dict[str, SenderMap] = {}
# A selector or label is told apart from an English word by a digit, an underscore or a hyphen.
_DISTINCT = re.compile(r"[\d_-]")


async def mapped(case: Path) -> SenderMap:
    """The case mapped once per session."""
    if case.name not in _MAPS:
        _MAPS[case.name] = (await replay(case)).map
    return _MAPS[case.name]


def terminal(result: SenderMap, *, evidence: bool) -> str:
    out = io.StringIO()
    text.render(result, Console(file=out, width=100, color_system=None), evidence=evidence)
    return out.getvalue()


def both(result: SenderMap, *, evidence: bool) -> tuple[str, str]:
    return terminal(result, evidence=evidence), markdown.render(result, evidence=evidence)


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_findings_precede_services(case: Path) -> None:
    result = await mapped(case)
    shown, md = both(result, evidence=False)
    if not (result.findings and result.senders):
        return
    first = min(shown.index(h) for h in ("\nFIX THESE\n", "\nNOTES\n") if h in shown)
    assert shown.index("\nAT A GLANCE\n") < first < shown.index("\nEVIDENCE, SERVICE BY SERVICE\n")
    assert md.index("## Needs attention") < md.index("## Senders")


async def test_findings_are_ordered_risk_warning_note() -> None:
    order = {"risk": 0, "warning": 1, "note": 2}
    for case in CASES:
        ranks = [order[f.severity] for f in view(await mapped(case), evidence=False).findings]
        assert ranks == sorted(ranks)


async def test_a_record_named_in_a_finding_appears_in_no_setup_clause() -> None:
    covered = 0
    for case in CASES:
        result = await mapped(case)
        for evidence in (False, True):
            shown = view(result, evidence=evidence)
            clauses = {s.name: s.setup for t in shown.tiers for s in t.services}
            for service in result.senders:
                for setup in service.setups:
                    for item in setup.items:
                        named = [
                            f
                            for f in result.findings
                            if service.name in f.title and set(item.evidence) & set(f.evidence)
                        ]
                        if item.state not in (State.MISSING, State.BROKEN) or not named:
                            continue
                        covered += 1
                        clause = clauses[service.name]
                        assert item.detail not in clause, (case.name, service.name, clause)
                        for f in named:
                            assert not any(str(e) in clause for e in f.evidence)
    assert covered >= 5  # the corpus holds such items, so the rule is tested


async def test_a_complete_setup_is_one_clause() -> None:
    complete = 0
    for case in CASES:
        result = await mapped(case)
        clauses = {s.name: s.setup for t in view(result, evidence=False).tiers for s in t.services}
        for service in result.senders:
            if service.setups and all(s.complete for s in service.setups):
                complete += 1
                assert clauses[service.name] == "setup complete"
    assert complete >= 10


def unanswered(result: SenderMap) -> set[str]:
    """The distinctive selectors and labels asked that nothing but the list of what was asked
    holds: no claim, finding, absence, gap or setup item names them."""
    data = json.dumps({k: v for k, v in result.to_dict().items() if k != "checked"})
    names: set[str] = set()
    for record in result.checked:
        names |= {s for s in record.dkim_selectors if f"{s}._domainkey" not in data}
        names |= {label for label in record.labels if f"{label}.{record.where}" not in data}
    return {n for n in names if _DISTINCT.search(n)}


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_names_asked_print_only_with_evidence(case: Path) -> None:
    result = await mapped(case)
    names = unanswered(result)
    assert names, "every case asks names nothing answered"
    assert all(record.names == () for record in view(result, evidence=False).asked)
    for rendered in both(result, evidence=False):
        said = [n for n in names if re.search(rf"(?<![\w.-]){re.escape(n)}(?![\w-])", rendered)]
        assert said == []
    for rendered in both(result, evidence=True):
        assert all(n in rendered for n in names)


async def test_the_markdown_view_of_allbirds_is_short() -> None:
    md = markdown.render(await mapped(CORPUS / "allbirds.com"))
    assert len(md.splitlines()) < 120


def service_view(shown: View, name: str) -> ServiceView:
    (found,) = [s for t in shown.tiers for s in t.services if s.name == name]
    return found


async def test_evidence_lines_are_one_per_kind() -> None:
    result = await mapped(CORPUS / "allbirds.com")
    m365 = service_view(view(result, evidence=False), "Microsoft 365")
    lines = [str(k) for k in m365.kinds]
    assert lines[0] == "MX: allbirds-com.mail.protection.outlook.com"  # the deciding kind first
    assert "DKIM keys: selector1, selector2 (both 2048 bit, by CNAME)" in lines
    assert "SPF: include:spf.protection.outlook.com" in lines
    assert all(k.records == () for k in m365.kinds)
    full = service_view(view(result, evidence=True), "Microsoft 365")
    assert sum(len(k.records) for k in full.kinds) == len(
        next(s for s in result.services if s.name == "Microsoft 365").claims
    )


def test_the_views_import_nothing_from_the_model() -> None:
    render = Path(text.__file__).parent
    for module in ("text.py", "markdown.py"):
        source = (render / module).read_text()
        assert "..model" not in source and "sendermap.model" not in source
        assert "from .view import" in source


def _cap(name: str, unasked: int = 82, cap: int = 27) -> Gap:
    happened = f"{unasked} of 109 not asked. The first {cap} were asked (cap {cap})."
    return Gap(f"DKIM selectors at {name}", happened, GapKind.DKIM, unasked, cap)


def test_gaps_of_one_kind_and_cap_collapse_to_one_group() -> None:
    names = ("marketing.glossier.com", "receipts.glossier.com", "send.glossier.com")
    (group,) = grouped_gaps([_cap(n) for n in names], "glossier.com")
    assert group.names == names and group.count == 246 and group.cap == 27
    assert str(group) == (
        "DKIM selectors at marketing, receipts and send.glossier.com: 82 of 109 not asked at "
        "each. The first 27 were asked (cap 27)."
    )


def test_gaps_with_different_caps_stay_apart() -> None:
    groups = grouped_gaps([_cap("a.glossier.com"), _cap("b.glossier.com", cap=30)], "glossier.com")
    assert [g.names for g in groups] == [("a.glossier.com",), ("b.glossier.com",)]


def test_names_that_share_no_parent_are_written_in_full() -> None:
    (group,) = grouped_gaps([_cap("mail.a.com"), _cap("mail.b.com")], "a.com")
    assert group.places() == ("mail.a.com", "mail.b.com")
    (group,) = grouped_gaps([_cap("a.com"), _cap("send.a.com")], "a.com")
    assert group.places() == ("a.com", "send.a.com")


def test_a_gap_without_a_name_carries_the_domain() -> None:
    gap = Gap("sending subdomains", "3 of 8 not checked.", GapKind.SUBDOMAINS, 3, 5)
    (group,) = grouped_gaps([gap], "glossier.com")
    assert group.names == ("glossier.com",) and not group.named
    assert str(group) == "sending subdomains: 3 of 8 not checked."


async def test_what_was_asked_leads_with_the_total() -> None:
    result = await mapped(CORPUS / "glossier.com")
    shown = view(result, evidence=False)
    assert shown.asked_total == f"{result.run.lookups} lookups at 4 names"
