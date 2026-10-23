"""SPF by evaluation in the map: where it runs, what a pass, a fail and an error leave behind,
which vendors it skips, the budget, and how the story and views show it."""

import io
import re
from dataclasses import replace

import pytest
from conftest import CHECKED, Zone
from rich.console import Console

from sendermap import catalog, engine, map_domain, story
from sendermap.model import Evidence, Gap, GapKind, Kind, Observed, SenderMap, State, Unknown
from sendermap.render import text
from sendermap.sources import spf, spf_checks

VALIMAIL = "%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email"
MX = "0 example-test.mail.protection.outlook.com"
M365 = "Microsoft 365"
CATALOG = catalog.load()
M365_IP = CATALOG.sending_ips[M365]


def asked_name(vendor: str, where: str = "example.test") -> str:
    """The name Valimail's macro include asks for one vendor's address."""
    ip, helo = CATALOG.sending_ips[vendor], CATALOG.sending_ip_host(vendor)
    return f"{ip}._ip.{helo}._ehlo.{where}._spf.vali.email"


def hosted(record: str = f"v=spf1 include:{VALIMAIL} -all", **answers: str) -> Zone:
    """Microsoft 365 in MX and a record behind a macro include; each answer is the record the
    service gives for one vendor's address, keyed by the vendor with spaces as underscores."""
    zone = Zone().add("example.test", "MX", MX).add("example.test", "TXT", record)
    for key, answer in answers.items():
        zone.add(asked_name(key.replace("_", " ")), "TXT", answer)
    return zone


async def mapped(zone: Zone) -> SenderMap:
    return await map_domain(
        "example.test", checked_at=CHECKED, resolver=zone, use_web=False, use_subdomains=False
    )


def spf_item(result: SenderMap, vendor: str = M365) -> tuple[State, tuple[Evidence, ...], str]:
    found = next(s for s in result.services if s.name == vendor)
    item = next(i for i in found.setups[0].items if i.record == "spf")
    return item.state, item.evidence, item.detail


async def test_a_pass_is_a_configured_claim_with_the_deciding_term_and_the_path() -> None:
    answer = f"v=spf1 ip4:{M365_IP} -all"
    result = await mapped(hosted(Microsoft_365=answer))
    service = next(s for s in result.services if s.name == M365)
    (claim,) = [c for c in service.claims if c.kind is Kind.SPF_EVALUATED]
    assert claim.kind.tier is not None and claim.kind.tier.value == "Configured"
    assert claim.where == "example.test"
    assert claim.evidence == Evidence(asked_name(M365), "TXT", f"ip4:{M365_IP}", CHECKED)
    assert claim.supporting == (Evidence(asked_name(M365), "TXT", answer, CHECKED),)
    state, evidence, _ = spf_item(result)
    assert state is State.PRESENT and evidence == (claim.evidence,)


async def test_a_fail_makes_no_claim_and_the_setup_reads_missing_with_the_verdict() -> None:
    result = await mapped(hosted(Microsoft_365="v=spf1 -all"))
    claims = [c for s in result.services for c in s.claims]
    assert not any(c.kind is Kind.SPF_EVALUATED for c in claims)
    state, evidence, detail = spf_item(result)
    assert state is State.MISSING
    # The include did not match, so the domain's own -all decided.
    assert evidence == (Evidence("example.test", "TXT", "-all", CHECKED),)
    assert detail == f"{M365_IP}, one of Microsoft 365's addresses, gets fail at -all"


async def test_without_evaluation_a_hosted_record_leaves_the_setup_not_checked() -> None:
    zone = hosted()
    zone.timeouts.add((asked_name(M365), "TXT"))
    result = await mapped(zone)
    state, _, detail = spf_item(result)
    assert state is State.NOT_CHECKED
    assert detail.startswith("managed through Valimail")
    (gap,) = [g for g in result.gaps if M365 in g.asked]
    assert gap == Gap(
        f"SPF evaluation at example.test for {M365}",
        f"temperror: lookup failed: {asked_name(M365)} TXT",
        GapKind.SPF,
        1,
    )


async def test_one_gap_names_every_vendor_an_error_ended_alike() -> None:
    # Past ten lookups the record fails the same way for everyone.
    record = f"v=spf1 include:_a.example.test include:_a.example.test include:{VALIMAIL} -all"
    zone = hosted(record).add("_a.example.test", "TXT", "v=spf1 a a a a a -all")
    zone.add("_a.example.test", "A", "192.0.2.1")
    result = await mapped(zone)
    (gap,) = [g for g in result.gaps if g.asked.startswith(spf_checks.EVALUATION)]
    assert gap.count == len(CATALOG.sending_ips)
    assert gap.happened == "permerror: more than 10 DNS lookups (at a)"
    assert all(vendor in gap.asked for vendor in CATALOG.sending_ips)


async def test_too_many_lookups_that_find_nothing_is_a_note_and_a_read_not_a_gap() -> None:
    # Three exists terms that find nothing for any address, as Salesforce's does for one it
    # does not send from; the third passes the limit of two.
    terms = " ".join(f"exists:%{{i}}.{n}.example.test" for n in ("_a", "_b", "_c"))
    record = f"v=spf1 {terms} include:{VALIMAIL} -all"
    result = await mapped(hosted(record))
    assert not [g for g in result.gaps if g.asked.startswith(spf_checks.EVALUATION)]
    (note,) = [f for f in result.findings if "permerror" in f.title]
    assert note.severity.value == "note"
    assert note.title == "SPF at example.test ends in permerror for some senders before its default"
    assert f"each of {len(CATALOG.sending_ips)} services" in note.detail
    assert note.evidence == (Evidence("example.test", "TXT", record, CHECKED),)
    state, _, detail = spf_item(result)
    assert state is State.MISSING
    assert detail.startswith(f"{M365_IP}, one of Microsoft 365's addresses, gets permerror: more")


async def test_evaluation_asks_nothing_where_the_walk_named_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def asked(zone: Zone) -> list[tuple[str, str]]:
        return sorted(set(zone.asked))

    plain = "v=spf1 include:spf.protection.outlook.com ip4:192.0.2.0/24 -all"
    with_ips = hosted(plain)
    await mapped(with_ips)
    without = replace(CATALOG, sending_ips={})
    monkeypatch.setattr(catalog, "load", lambda: without)  # the module the engine reads
    without_ips = hosted(plain)
    await mapped(without_ips)
    assert asked(with_ips) == asked(without_ips)


async def test_a_vendor_the_walk_credited_is_not_evaluated_there() -> None:
    record = f"v=spf1 include:spf.protection.outlook.com include:{VALIMAIL} -all"
    zone = hosted(record).add("spf.protection.outlook.com", "TXT", "v=spf1 ip4:40.92.0.0/15 -all")
    await mapped(zone)
    names = {name for name, _ in zone.asked}
    assert asked_name(M365) not in names
    assert asked_name("Google Workspace") in names


def test_the_walk_says_when_it_could_not_name_everything() -> None:
    assert spf.SpfTree().unnamed is None
    assert spf.SpfTree(hosted_by="Valimail").unnamed == "managed through Valimail"
    read = spf.SpfTree(hosted_by="EasyDMARC", flattened=["EasyDMARC"])
    assert read.unnamed is None
    assert spf.SpfTree(macros=["%{i}.x.test"]).unnamed == "a macro include"
    assert spf.SpfTree(too_deep=["deep.test"]).unnamed == "includes more than 10 levels deep"


def test_a_flattened_record_needs_evaluating_only_with_ranges_left_unknown() -> None:
    tree = spf.SpfTree(hosted_by="EasyDMARC", flattened=["EasyDMARC"])
    evidence = Evidence("x.easydmarc.pro", "TXT", "ip4:198.51.100.0/24", CHECKED)
    unknown = Unknown("IP range in SPF", "198.51.100.0/24 (AS64500)", "example.test", evidence)
    assert engine._partial("example.test", tree, Observed()) is None
    elsewhere = Observed(unknowns=(replace(unknown, where="mail.example.test"),))
    assert engine._partial("example.test", tree, elsewhere) is None
    partial = engine._partial("example.test", tree, Observed(unknowns=(unknown,)))
    assert partial == spf_checks.Partial("example.test", "flattened by EasyDMARC, 1 range unknown")


async def test_past_the_budget_a_gap_names_the_vendors_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(spf_checks, "BUDGET", 10)
    zone = hosted()
    result = await mapped(zone)
    asked = [n for n, _ in dict.fromkeys(zone.asked) if n.endswith("._spf.vali.email")]
    assert len(asked) == 2 * spf_checks.WAVE  # the second wave started under the budget
    vendors = list(CATALOG.sending_ips)
    (left,) = [g for g in result.gaps if g.cap]
    assert left.asked == f"SPF evaluation at example.test for {', '.join(vendors[16:])}"
    assert left.happened == "not evaluated: the budget of 10 lookups per map was spent (cap)"
    assert (left.kind, left.count, left.cap) == (GapKind.SPF, len(vendors) - 16, 10)


def test_the_story_counts_evaluation_gaps_apart_from_the_walks() -> None:
    gaps = (
        Gap("SPF: TXT at example.test", "lookup failed", GapKind.SPF, 1),
        Gap(f"{spf_checks.EVALUATION} at example.test for A, B", "permerror: x", GapKind.SPF, 2),
        Gap(f"{spf_checks.EVALUATION} at example.test for C", "not evaluated", GapKind.SPF, 1, 150),
    )
    assert story._spf(gaps) == (
        "one SPF record whose lookup failed and SPF evaluation for two vendors (an error) and "
        "SPF evaluation for one vendor past its 150 lookups"
    )


async def test_the_claim_shows_under_its_service_like_any_other() -> None:
    answer = f"v=spf1 ip4:{M365_IP} -all"
    result = await mapped(hosted(Microsoft_365=answer))
    console = Console(file=io.StringIO(), width=200, color_system=None)
    text.render(result, console, evidence=True)
    out = console.file.getvalue()  # type: ignore[attr-defined]
    assert re.search(r"SPF passes its address +ip4:", out)
    assert f"{asked_name(M365)} TXT ip4:{M365_IP}" in out
