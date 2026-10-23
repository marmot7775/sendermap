"""The story: at most five sentences in a fixed order, each built only from objects in the map,
every name a service of the map and every number the map's own count."""

import re
from dataclasses import replace
from html import escape
from pathlib import Path

import pytest
from conftest import CHECKED, Zone
from rich.console import Console

from sendermap import catalog, map_domain, story
from sendermap.model import (
    Checked,
    Claim,
    Denial,
    Evidence,
    Finding,
    Gap,
    GapKind,
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
    Unknown,
)
from sendermap.render import html, markdown, text
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
        run=Run(CHECKED, 0.0, 0, "fake zone"),
        findings=(
            Finding(Severity.RISK, "The s1 DKIM record points at a name that does not exist", ""),
            Finding(Severity.RISK, f"SPF at {DOMAIN} needs 14 DNS lookups", ""),
            Finding(Severity.WARNING, "A warning the story leaves out", ""),
            Finding(Severity.NOTE, "A note the story leaves out", ""),
        ),
        gaps=(
            Gap(
                "sending subdomains", "not searched: subdomain checks were turned off", GapKind.OFF
            ),
            Gap("the website", "not read: web checks were turned off (--no-web)", GapKind.OFF),
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
        "Not checked: the website (turned off) and sending subdomains (turned off)."
    )


def test_a_map_that_reaches_no_sentence() -> None:
    assert story.write(SenderMap(DOMAIN, (), Run(CHECKED, 0.0, 0, "fake zone"))) == ""


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
        Run(CHECKED, 0.0, 0, "fake zone"),
    )
    assert story.receivers(mapped) == f"Microsoft 365 receives the domain's mail and {words}."


def test_a_receiver_with_no_setup_says_only_that_it_receives() -> None:
    mapped = SenderMap(DOMAIN, (service("Fastmail", Kind.MX),), Run(CHECKED, 0.0, 0, "fake zone"))
    assert story.write(mapped) == "Fastmail receives the domain's mail."


def receiver_at_risk(state: State, *titles: str) -> SenderMap:
    return SenderMap(
        DOMAIN,
        (service("Google Workspace", Kind.MX, DOMAIN, dkim("Google Workspace", state)),),
        Run(CHECKED, 0.0, 0, "fake zone"),
        findings=tuple(Finding(Severity.RISK, f"Google Workspace{t}", "") for t in titles),
    )


def test_a_receivers_risks_fold_into_one_clause_and_are_not_said_again() -> None:
    mapped = receiver_at_risk(
        State.MISSING,
        " receives the domain's mail and is not in its SPF",
        " receives the domain's mail and does not sign it",
    )
    assert story.write(mapped) == (
        "The map shows two risks: Google Workspace receives the domain's mail, is not in its SPF "
        "and does not sign it."
    )


def test_a_receiver_at_risk_whose_key_is_in_place_still_says_so() -> None:
    mapped = receiver_at_risk(State.PRESENT, " receives the domain's mail and is not in its SPF")
    assert story.write(mapped) == (
        "The map shows one risk: Google Workspace receives the domain's mail and is not in its "
        "SPF. Google Workspace receives the domain's mail and has a DKIM key in place to sign it."
    )


def test_likely_alone_and_one_of_each() -> None:
    mapped = SenderMap(
        DOMAIN, (service("Customer.io", Kind.DKIM_NAME),), Run(CHECKED, 0.0, 0, "fake zone")
    )
    assert story.write(mapped) == (
        "One service is likely to send as the domain from a DKIM key name alone (Customer.io)."
    )


def gap(kind: GapKind, count: int = 0, cap: int = 0, asked: str = "asked") -> Gap:
    return Gap(asked, f"raw words for {asked}", kind, count, cap)


def unchecked(*gaps: Gap) -> str:
    return story.write(SenderMap(DOMAIN, (), Run(CHECKED, 0.0, 0, "fake zone"), gaps=gaps))


def test_the_last_sentence_is_one_clause_per_kind_counted_in_plain_words() -> None:
    assert unchecked(
        gap(GapKind.OFF, asked=f"certificate transparency, crt.sh: GET https://crt.sh/?q={DOMAIN}"),
        *(gap(GapKind.DKIM, 74, 27, f"DKIM selectors at s{n}.acme.test") for n in range(5)),
        gap(GapKind.DKIM, 1, asked="DKIM keys at acme.test"),
        gap(GapKind.SUBDOMAINS, 6),
        gap(GapKind.NETWORKS, 12, 24),
        gap(GapKind.OFF, asked="the website"),
    ) == (
        "Not checked: the website (turned off), DKIM selectors past the first 27 on five "
        "subdomains and one that could not be read, network owners for 12 of 36 ranges, six "
        "subdomains whose DNS failed to answer, and the crt.sh certificate log (read only with "
        "--ct)."
    )


@pytest.mark.parametrize(
    ("gaps", "clause"),
    [
        ((gap(GapKind.WEBSITE),), "the website (could not be read)"),
        ((gap(GapKind.WEBSITE, cap=2_000_000),), "the website past its first two million bytes"),
        ((gap(GapKind.PAGE),), "the subprocessor page (could not be read)"),
        ((gap(GapKind.DKIM, 3),), "three DKIM selectors that could not be read"),
        (
            (gap(GapKind.SPF, 1), gap(GapKind.SPF, 2, 10)),
            "one SPF record whose lookup failed and two SPF includes more than ten levels deep",
        ),
        ((gap(GapKind.MX, 1),), "MX at one name whose lookup failed"),
        ((gap(GapKind.MX),), "MX (could not be read)"),
        (
            (
                gap(GapKind.NETWORKS, 18, 24),
                gap(GapKind.NETWORKS, 24, 24),
                gap(GapKind.NETWORKS, 2),
            ),
            "network owners for 42 of 90 ranges at two names and for two whose lookups failed",
        ),
        ((gap(GapKind.NETWORKS, 3),), "network owners for three ranges whose lookups failed"),
        (
            (gap(GapKind.SUBDOMAINS, 4, 30),),
            "sending subdomains past the first 30 (four more)",
        ),
        ((gap(GapKind.SUBDOMAINS),), "sending subdomains (could not be read)"),
        (
            (
                gap(GapKind.CERTIFICATE_LOG),
                gap(GapKind.CERTIFICATE_LOG, 2),
                gap(GapKind.CERTIFICATE_LOG, 34, 2),
            ),
            "one certificate log that could not be read and two names from certificate logs "
            "whose lookups failed and 34 names from certificate logs left out by a limit",
        ),
        ((gap(GapKind.LABELS, 2),), "bounce and tracking CNAMEs at two names whose lookups failed"),
        ((gap(GapKind.REPORTS, 1),), "report addresses at one name whose lookup failed"),
        ((gap(GapKind.TOKENS),), "verification tokens (could not be read)"),
        ((gap(GapKind.MTA_STS),), "the MTA-STS policy (could not be read)"),
        (
            (gap(GapKind.OFF, asked="MTA-STS policy: GET https://mta-sts.acme.test/x"),),
            "the MTA-STS policy (turned off with the website and subdomains)",
        ),
        ((gap(GapKind.OTHER), gap(GapKind.OTHER)), "two other checks (could not be read)"),
    ],
)
def test_each_kind_reads_in_plain_words(gaps: tuple[Gap, ...], clause: str) -> None:
    assert unchecked(*gaps) == f"Not checked: {clause}."


def test_gaps_in_other_services_published_ranges_are_counted_not_named() -> None:
    gaps = (
        gap(GapKind.PUBLISHED_RANGES, cap=3, asked="published ranges: SPF of HubSpot"),
        gap(GapKind.PUBLISHED_RANGES, cap=3, asked="published ranges: SPF of Mimecast"),
        gap(GapKind.PUBLISHED_RANGES, asked="published ranges: SPF of Mailgun"),
    )
    assert unchecked(*gaps) == (
        "Not checked: the IP ranges three services publish in their own SPF (past three include "
        "levels for two and lookups failed for one)."
    )
    assert unchecked(gaps[2]) == (
        "Not checked: the IP ranges one service publishes in its own SPF (lookups failed)."
    )


# ------------------------------------------------------------------ a domain with nothing


def nothing(*gaps: Gap, **checked: object) -> SenderMap:
    here = Checked(DOMAIN, **checked)  # type: ignore[arg-type]
    return SenderMap(DOMAIN, (), Run(CHECKED, 0.0, 0, "fake zone"), gaps=gaps, checked=(here,))


def test_a_map_with_no_sender_states_what_was_checked() -> None:
    selectors = tuple(f"s{n}" for n in range(106))
    assert story.write(nothing(dkim_selectors=selectors, denial=Denial.CLASSIC)) == (
        "No sending service shows in DNS for acme.test: no MX, no sender in SPF, and no DKIM "
        "key at the 106 names asked."
    )


def test_a_null_mx_and_a_dkim_wildcard_are_said_as_they_are() -> None:
    null = Finding(Severity.NOTE, "The domain accepts no mail", "")
    mapped = replace(nothing(denial=Denial.WILDCARD), findings=(null,))
    assert story.write(mapped) == (
        "No sending service shows in DNS for acme.test: a null MX that says it accepts no mail, "
        "no sender in SPF, and a wildcard that answers every DKIM name."
    )


def test_a_part_whose_check_has_a_gap_is_left_to_the_last_sentence() -> None:
    mapped = nothing(gap(GapKind.MX, 1), gap(GapKind.DKIM, 2), dkim_selectors=("s1", "s2"))
    assert story.write(mapped) == (
        "No sending service shows in DNS for acme.test: no sender in SPF. Not checked: two DKIM "
        "selectors that could not be read and MX at one name whose lookup failed."
    )


def test_no_absence_is_stated_beside_an_unrecognised_sender_or_without_a_record_of_asking() -> None:
    evidence = Evidence(DOMAIN, "MX", "10 mx.acme.test", CHECKED)
    unknown = Unknown("mail server", "mx.acme.test", DOMAIN, evidence)
    assert story.write(replace(nothing(), unknowns=(unknown,))) == ""
    assert story.write(SenderMap(DOMAIN, (), Run(CHECKED, 0.0, 0, "fake zone"))) == ""


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
    counted = paragraph.partition("Not checked: ")[0]
    for word, names in re.findall(rf"\b({_COUNT})\b[^();:]*?\(([^()]+)\)", counted, re.I):
        assert _count(word) == len(names.split(", ")), (word, names)
    assert paragraph.count("Not checked:") == (1 if mapped.gaps else 0)
    last = paragraph.partition("Not checked: ")[2]
    assert "://" not in last and "((" not in last and not re.search(r"\([^()]*\(", last)
    assert set(re.findall(r"--[\w-]+", last)) <= {"--ct"}
    assert not any(g.happened in last for g in mapped.gaps)
    # The counts in the last sentence are the map's own.
    if budget := [g for g in mapped.gaps if g.kind is GapKind.DKIM and g.cap]:
        assert f"on {story.number(len(budget))} subdomain" in last
    if ranges := [g for g in mapped.gaps if g.kind is GapKind.NETWORKS and g.cap]:
        left, total = sum(g.count for g in ranges), sum(g.count + g.cap for g in ranges)
        match = re.search(r"network owners for (\w+) of (\w+) ranges", last)
        assert match and (_count(match[1]), _count(match[2])) == (left, total)
    if failed := sum(g.count for g in mapped.gaps if g.kind is GapKind.SUBDOMAINS and not g.cap):
        assert f"{story.number(failed)} subdomain{'s' if failed > 1 else ''} whose" in last


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
    said = story.sentences(mapped)
    assert len(said) > 1 and shown[4 : 4 + len(said)] == said  # under the panel, one per line
    md = markdown.render(mapped).split("\n")
    assert md[0] == f"# Sendermap: {DOMAIN}" and md[4] == mapped.story  # under the counts
    assert mapped.to_dict()["story"] == mapped.story
    page = html.html(mapped)
    assert f'<p class="story">{escape(mapped.story)}</p>' in page
    assert page.index('class="story"') < page.index("Needs attention")
    # The page puts the ring map right after the story.
    js = (Path(text.__file__).parent.parent / "web" / "static" / "app.js").read_text()
    assert "story.after(figure)" in js


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


async def test_a_domain_that_does_not_exist_says_so_first() -> None:
    result = await map_domain(
        "gone.example", checked_at=CHECKED, resolver=Zone(), use_web=False, use_subdomains=False
    )
    (finding,) = [f for f in result.findings if f.title == "The domain does not exist in DNS"]
    assert str(finding.evidence[0]) == "gone.example MX no such name"
    assert result.story.startswith(
        "gone.example does not exist in DNS, so nothing sends or receives mail as it."
    )


async def test_a_domain_that_does_not_exist_is_asked_nothing_more() -> None:
    zone = Zone()
    result = await map_domain("gone.example", checked_at=CHECKED, resolver=zone, use_web=False)
    assert result.run.lookups == 1 and result.services == () and result.gaps == ()
    assert (
        result.story
        == "gone.example does not exist in DNS, so nothing sends or receives mail as it."
    )
