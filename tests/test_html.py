"""The web page's view: the View as an HTML fragment, every string escaped, the sections in the
View's order, and the records in full and the names asked inside details elements alone."""

import re
from html import escape
from pathlib import Path

import pytest
from conftest import CHECKED
from test_view import CASES, mapped

from sendermap.model import (
    Checked,
    Claim,
    Evidence,
    Finding,
    Kind,
    Role,
    Run,
    SenderMap,
    Service,
    Severity,
    Tier,
    Unknown,
)
from sendermap.render import markdown, view
from sendermap.render.html import html, slug

DOMAIN = "acme.test"
HOSTILE = '<script>alert(1)</script> "quoted"'
SECTIONS = (
    "Needs attention",
    "In use",
    "Configured",
    "Likely",
    "Account only",
    "Reports go to",
    "Claimed senders",
    "Not recognised",
    "Certificate transparency",
    "Checked and not there",
    "Not checked",
    "What was asked",
)
_DETAILS = re.compile(r"<details\b.*?</details>", re.S)
_TITLES = re.compile(r'<h3 class="section-title">([^<]*)</h3>')


def hostile_map() -> SenderMap:
    """A map whose service name, record value and finding detail carry markup and a quote."""
    evidence = Evidence(DOMAIN, "TXT", f"v=spf1 include:{HOSTILE}", CHECKED)
    claim = Claim(HOSTILE, Kind.SPF_INCLUDE, DOMAIN, evidence)
    service = Service(HOSTILE, "Other", Tier.CONFIGURED, Role.SENDER, (claim,))
    return SenderMap(
        domain=DOMAIN,
        services=(service,),
        run=Run(CHECKED, 0.0, 3, "fake zone"),
        findings=(Finding(Severity.RISK, "A finding", f"Detail {HOSTILE}", (evidence,)),),
        unknowns=(Unknown("SPF include", HOSTILE, DOMAIN, evidence),),
        checked=(Checked(DOMAIN, dkim_selectors=(HOSTILE,)),),
    )


def test_every_string_from_dns_is_escaped() -> None:
    page = html(hostile_map())
    assert "<script" not in page
    assert '"quoted"' not in page
    assert escape(HOSTILE, quote=True) in page
    assert f'id="service-{slug(HOSTILE)}"' in page
    # Every tag left is one the renderer writes.
    tags = set(re.findall(r"</?([a-z0-9]+)", page))
    assert tags <= {
        "header",
        "h2",
        "h3",
        "h4",
        "p",
        "section",
        "div",
        "article",
        "span",
        "ul",
        "li",
        "details",
        "summary",
    }


def test_a_card_carries_its_id() -> None:
    assert slug("Microsoft 365") == "microsoft-365"
    assert slug("Customer.io") == "customer-io"
    assert slug(HOSTILE) == "-script-alert-1---script---quoted-"


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_sections_follow_the_views_order(case: Path) -> None:
    result = await mapped(case)
    page = html(result)
    titles = _TITLES.findall(page)
    assert titles == [t for t in SECTIONS if t in titles]
    assert page.startswith('<header class="view-head">\n<h2>')
    for s in result.senders:
        assert f'<article class="card" id="service-{slug(s.name)}">' in page


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_only_details_hold_the_records_and_the_names(case: Path) -> None:
    result = await mapped(case)
    page = html(result)
    outside = _DETAILS.sub("", page)
    inside = "".join(_DETAILS.findall(page))
    # What the views show without evidence may also stand outside.
    brief = markdown.render(result, evidence=False)
    full = view(result, evidence=True)
    held: list[str] = []
    for tier in full.tiers:
        for service in tier.services:
            held += [r for kind in service.kinds for r in kind.records]
            if service.setup != service.brief:
                held.append(service.setup)
    held += [r for f in full.findings for r in f.records]
    held += [r for u in full.unknowns for r in u.records[1:]]
    held += [", ".join(names) for a in full.asked for _, names in a.names]
    for line in held:
        assert escape(line, quote=True) in inside
        if line not in brief:
            assert escape(line, quote=True) not in outside, line


def test_the_names_asked_sit_under_names_asked() -> None:
    page = html(hostile_map())
    (names,) = [d for d in _DETAILS.findall(page) if "<summary>Names asked</summary>" in d]
    assert escape(HOSTILE, quote=True) in names
