"""The story: at most five sentences in a fixed order, each built only from objects in the map,
every name a service of the map and every number the map's own count."""

import re
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import CHECKED
from rich.console import Console

from sendermap import catalog, story
from sendermap.model import (
    Claim,
    Evidence,
    Finding,
    Gap,
    Kind,
    Need,
    Role,
    Run,
    SenderMap,
    Service,
    Setup,
    SetupItem,
    Severity,
    State,
    Tier,
)
from sendermap.render import markdown, text
from sendermap.setup import line
from sendermap.testing import replay

DOMAIN = "acme.test"
CORPUS = Path(__file__).parent / "corpus"
CASES = sorted(p for p in CORPUS.iterdir() if (p / "case.json").exists())


def service(name: str, kind: Kind, where: str = DOMAIN, *setups: Setup) -> Service:
    claim = Claim(name, kind, where, Evidence(where, "TXT", f"{name} record", CHECKED))
    role = Role.REPORTING if kind.tier is None else Role.SENDER
    return Service(name, catalog.load().category(name), kind.tier, role, (claim,), setups)


def dkim(name: str, state: State) -> Setup:
    return Setup(name, DOMAIN, (SetupItem("dkim", Need.REQUIRED, state),), state is State.PRESENT)


def every_sentence() -> SenderMap:
    return SenderMap(
        domain=DOMAIN,
        services=(
            service("Google Workspace", Kind.MX, DOMAIN, dkim("Google Workspace", State.MISSING)),
            service("Mimecast", Kind.MX),
            service("SendGrid", Kind.SPF_INCLUDE),
            service("Mailchimp", Kind.DKIM_CNAME),
            service("Postmark", Kind.RETURN_PATH),
            service("Customer.io", Kind.DKIM_NAME),
            service("Gorgias", Kind.WEBSITE),
            service("Mandrill", Kind.DKIM_NAME),
            service("Atlassian", Kind.TOKEN),
            service("Agari", Kind.DMARC_REPORTS),
            service("URIports", Kind.TLSRPT_REPORTS),
        ),
        run=Run(CHECKED, 0.0, 0),
        findings=(
            Finding(Severity.RISK, "The s1 DKIM record points at a name that does not exist", ""),
            Finding(Severity.RISK, f"SPF at {DOMAIN} needs 14 DNS lookups", ""),
            Finding(Severity.WARNING, "A warning the story leaves out", ""),
            Finding(Severity.NOTE, "A note the story leaves out", ""),
        ),
        gaps=(
            Gap("sending subdomains", "not searched: subdomain checks were turned off"),
            Gap("the website", "not read: web checks were turned off (--no-web)"),
        ),
    )


def test_a_map_that_reaches_every_sentence() -> None:
    assert story.write(every_sentence()) == (
        "The map shows two risks: the s1 DKIM record points at a name that does not exist; "
        "SPF at acme.test needs 14 DNS lookups. "
        "Google Workspace receives the domain's mail and has no DKIM key in place to sign it; "
        "Mimecast stands in front of the domain's mail as a security gateway, so the mailbox "
        "provider is not visible from MX. "
        "Three other services are set up to send as the domain: two transactional (SendGrid, "
        "Postmark), one marketing (Mailchimp); three more are likely: two from a DKIM key name "
        "alone (Customer.io, Mandrill), one from a script or stylesheet the website loads "
        "(Gorgias). "
        "One service shows an account and nothing set up to send (Atlassian); DMARC reports "
        "go to Agari; TLS reports go to URIports. "
        "Not checked: the website (not read: web checks were turned off (--no-web)); sending "
        "subdomains (not searched: subdomain checks were turned off)."
    )


def test_a_map_that_reaches_no_sentence() -> None:
    assert story.write(SenderMap(DOMAIN, (), Run(CHECKED, 0.0, 0))) == ""


@pytest.mark.parametrize(
    ("state", "words"),
    [
        (State.PRESENT, "has a DKIM key in place to sign it"),
        (State.MISSING, "has no DKIM key in place to sign it"),
        (State.BROKEN, "its only DKIM key is broken"),
        (State.NOT_CHECKED, "whether it has a DKIM key could not be checked"),
    ],
)
def test_the_receiver_sentence_says_what_the_dkim_setup_shows(state: State, words: str) -> None:
    mapped = SenderMap(
        DOMAIN,
        (service("Microsoft 365", Kind.MX, DOMAIN, dkim("Microsoft 365", state)),),
        Run(CHECKED, 0.0, 0),
    )
    assert story.receivers(mapped) == f"Microsoft 365 receives the domain's mail and {words}."


def test_a_receiver_with_no_setup_says_only_that_it_receives() -> None:
    mapped = SenderMap(DOMAIN, (service("Fastmail", Kind.MX),), Run(CHECKED, 0.0, 0))
    assert story.write(mapped) == "Fastmail receives the domain's mail."


def test_likely_alone_and_one_of_each() -> None:
    mapped = SenderMap(DOMAIN, (service("Customer.io", Kind.DKIM_NAME),), Run(CHECKED, 0.0, 0))
    assert story.write(mapped) == (
        "One service is likely to send as the domain from a DKIM key name alone (Customer.io)."
    )


def test_gaps_in_other_services_published_ranges_are_counted_not_named() -> None:
    cap = "includes more than 3 levels deep not read (cap)"
    gaps = (
        Gap("published ranges: SPF of HubSpot", cap),
        Gap("DKIM selectors at mail.acme.test", "74 of 106 not asked (cap)"),
        Gap("published ranges: SPF of Mimecast", cap),
        Gap("published ranges: SPF of Mailgun", "lookup failed"),
    )
    mapped = SenderMap(DOMAIN, (), Run(CHECKED, 0.0, 0), gaps=gaps)
    assert story.write(mapped) == (
        "Not checked: DKIM selectors at mail.acme.test (74 of 106 not asked (cap)); the IP ranges "
        f"two services publish in their own SPF ({cap}); the IP ranges one service publishes in "
        "its own SPF (lookup failed)."
    )


def test_numbers_are_words_to_twenty_and_digits_past() -> None:
    assert [story.number(n) for n in (1, 11, 20, 21)] == ["one", "eleven", "twenty", "21"]


# ------------------------------------------------------------------ names and counts

_WORDS = {story.number(n): n for n in range(1, 21)}
_COUNT = "|".join(_WORDS)


def _count(word: str) -> int:
    return _WORDS[word.lower()] if word.lower() in _WORDS else int(word)


def _names_in(paragraph: str) -> set[str]:
    """Every vendor name the paragraph uses, longest first so a name inside another is not
    counted twice."""
    found: set[str] = set()
    for name in sorted(catalog.load().services, key=len, reverse=True):
        pattern = rf"(?<![\w.]){re.escape(name)}(?![\w])"
        if re.search(pattern, paragraph):
            found.add(name)
            paragraph = re.sub(pattern, "", paragraph)
    return found


def check(mapped: SenderMap) -> None:
    paragraph = story.write(mapped)
    assert _names_in(paragraph) <= {s.name for s in mapped.services}
    senders = mapped.senders
    expected = {
        r"The map shows (\w+) risks?": sum(f.severity is Severity.RISK for f in mapped.findings),
        r"(\w+)(?: other)? services? (?:is|are) set up to send": sum(
            s.tier is Tier.CONFIGURED for s in senders
        ),
        r"(\w+) (?:more|(?:other )?services?) (?:is|are) likely": sum(
            s.tier is Tier.LIKELY for s in senders
        ),
        r"(\w+) services? shows? an account": sum(s.tier is Tier.ACCOUNT_ONLY for s in senders),
    }
    for pattern, count in expected.items():
        match = re.search(pattern, paragraph, re.IGNORECASE)
        assert (_count(match.group(1)) if match else 0) == count, pattern
    # Each counted group's number is the number of names in its brackets.
    for word, names in re.findall(rf"\b({_COUNT})\b[^();:]*?\(([^()]+)\)", paragraph, re.I):
        assert _count(word) == len(names.split(", ")), (word, names)
    assert paragraph.count("Not checked:") == (1 if mapped.gaps else 0)
    if mapped.gaps:
        assert paragraph.split("Not checked: ")[1].count(" (") >= len(mapped.gaps)


def test_names_and_counts_on_the_fake_map() -> None:
    check(every_sentence())


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
async def test_names_and_counts_on_every_corpus_case(case: Path) -> None:
    replayed = await replay(case)
    check(replayed.map)
    assert replayed.map.story == story.write(replayed.map)


# ------------------------------------------------------------------ the views


def test_every_view_carries_the_story() -> None:
    mapped = replace(every_sentence(), story=story.write(every_sentence()))
    console = Console(record=True, width=2000)
    text.render(mapped, console)
    shown = console.export_text().splitlines()
    assert shown[3] == mapped.story  # under the headline's panel
    md = markdown.render(mapped).split("\n")
    assert md[:3] == [f"# Sendermap: {DOMAIN}", "", mapped.story]
    assert mapped.to_dict()["story"] == mapped.story
    js = (Path(text.__file__).parent.parent / "web" / "static" / "app.js").read_text()
    assert '$("story").textContent = map.story' in js
    html = (Path(text.__file__).parent.parent / "web" / "static" / "index.html").read_text()
    assert html.index('id="story"') < html.index('id="map"')


# ------------------------------------------------------------------ optional wording


def test_an_optional_record_that_is_missing_reads_not_used() -> None:
    items = (
        SetupItem("spf", Need.REQUIRED, State.MISSING, asked="TXT at acme.test", detail="no SPF"),
        SetupItem(
            "return_path",
            Need.OPTIONAL,
            State.MISSING,
            asked="CNAME at 23 labels under acme.test",
            detail="no CNAME into sendgrid.net at the 23 labels asked",
        ),
    )
    assert line(Setup("SendGrid", DOMAIN, items, False)) == (
        "Setup at acme.test: SPF missing (no SPF), "
        "bounce CNAME not used (optional, CNAME at 23 labels under acme.test)."
    )
    js = (Path(text.__file__).parent.parent / "web" / "static" / "app.js").read_text()
    assert "not used (optional, ${i.asked})" in js
