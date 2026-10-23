"""The _domainkey triage: the wildcard check and _domainkey itself, read together, say how the
zone denies names, and when it denies them classically whether any selector exists. A name
shown absent is an Absence with the negative answers as its evidence."""

import json

import httpx
from conftest import CHECKED, Zone, context
from rich.console import Console

from sendermap import map_domain
from sendermap.model import Claim, Denial, Evidence, Kind, Observed, Severity
from sendermap.render import markdown, text
from sendermap.sources import CANARY, dkim

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392
NAMES = [f"s{n}" for n in range(1, 21)]  # a ranked sweep of twenty names
SPF = Evidence("example.com", "TXT", "v=spf1 include:hubspotemail.net ~all", CHECKED)
BACKED = {"hs1": Claim("HubSpot", Kind.SPF_INCLUDE, "example.com", SPF)}


def asked_under(zone: Zone, where: str = "example.com") -> list[str]:
    suffix = f"._domainkey.{where}"
    return [
        n.removesuffix(suffix)
        for n, t in zone.asked
        if t == "TXT" and n.endswith(suffix) and not n.startswith(CANARY)
    ]


async def scan(zone: Zone) -> Observed:
    return await dkim.collect(context(zone), "example.com", [*NAMES, "hs1"], BACKED)


async def test_no_domainkey_in_a_classic_zone_is_an_absence_and_only_the_check_runs() -> None:
    zone = Zone()
    observed = await scan(zone)
    check = [*NAMES[: dkim.CHECK_PROBES], "hs1"]
    assert asked_under(zone) == check
    (checked,) = observed.checked
    assert checked.denial is Denial.CLASSIC and list(checked.dkim_selectors) == check
    (absence,) = observed.absences
    assert absence.asked == "DKIM keys at example.com"
    assert absence.happened.startswith(
        "no selectors exist: _domainkey.example.com does not exist, so the 21-name sweep was "
        "skipped"
    )
    assert [str(e) for e in absence.evidence] == [
        "_domainkey.example.com TXT no such name",
        f"{CANARY}._domainkey.example.com TXT no such name",
    ]
    assert all(e.checked_at == CHECKED for e in absence.evidence)
    assert observed.gaps == ()


async def test_a_key_under_a_denied_node_is_a_note_and_the_full_sweep_runs() -> None:
    zone = Zone(nxdomain={"_domainkey.example.com"}).add("s3._domainkey.example.com", "TXT", KEY)
    observed = await scan(zone)
    assert observed.absences == () and observed.gaps == ()
    (finding,) = [f for f in observed.findings if "does not exist" in f.title]
    assert finding.severity is Severity.NOTE
    assert finding.title == "DNS says _domainkey.example.com does not exist, but a key sits under it"
    assert [str(e).split(" TXT ")[0] for e in finding.evidence] == [
        "_domainkey.example.com",
        "s3._domainkey.example.com",
    ]
    assert set(asked_under(zone)) == {*NAMES, "hs1"}
    assert [u.value for u in observed.unknowns] == ["s3"]


async def test_selectors_that_exist_but_none_asked_is_an_absence_of_the_names_asked() -> None:
    zone = Zone().selectors_exist("example.com")
    observed = await scan(zone)
    assert set(asked_under(zone)) == {*NAMES, "hs1"}
    (absence,) = observed.absences
    assert absence.happened == "selectors exist but none of the 21 names asked is one"
    assert [str(e) for e in absence.evidence] == [
        "_domainkey.example.com TXT no record of this type"
    ]


async def test_a_key_found_by_the_sweep_is_no_absence() -> None:
    zone = Zone().add("s17._domainkey.example.com", "TXT", KEY)
    observed = await scan(zone)
    assert observed.absences == () and observed.gaps == ()
    assert [u.value for u in observed.unknowns] == ["s17"]


async def test_a_revoked_key_is_a_selector_so_no_absence() -> None:
    zone = Zone().add("s17._domainkey.example.com", "TXT", "v=DKIM1; p=")
    assert (await scan(zone)).absences == ()


async def test_compact_denial_says_nothing_by_rcode_so_the_sweep_runs_with_no_absence() -> None:
    zone = Zone(compact=True)
    observed = await scan(zone)
    assert set(asked_under(zone)) == {*NAMES, "hs1"}
    assert observed.absences == ()
    (checked,) = observed.checked
    assert checked.denial is Denial.NONE_BY_RCODE


async def test_a_wildcard_key_is_the_wildcard_denial() -> None:
    zone = Zone().add("*._domainkey.example.com", "TXT", KEY)
    observed = await scan(zone)
    (checked,) = observed.checked
    assert checked.denial is Denial.WILDCARD and observed.absences == ()


async def test_a_failed_wildcard_check_is_unknown_denial_and_the_existing_gap() -> None:
    zone = Zone(failing={f"{CANARY}._domainkey.example.com"})
    observed = await scan(zone)
    (checked,) = observed.checked
    assert checked.denial is Denial.UNKNOWN and observed.absences == ()
    assert set(asked_under(zone)) == {*NAMES, "hs1"}
    assert any(g.asked.startswith("wildcard check") for g in observed.gaps)


async def test_a_subdomain_with_no_selectors_has_no_cap_gap(offline: httpx.AsyncClient) -> None:
    zone = Zone().add("email.acme.test", "TXT", "v=spf1 include:mailgun.org ~all")
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=zone, http=offline, use_web=False
    )
    assert "DKIM selectors at email.acme.test" not in {g.asked for g in result.gaps}
    assert {a.asked for a in result.absences} == {
        "DKIM keys at acme.test",
        "DKIM keys at email.acme.test",
    }


async def test_json_gains_absences_and_denial(offline: httpx.AsyncClient) -> None:
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=Zone(), http=offline, use_web=False
    )
    data = json.loads(json.dumps(result.to_dict()))
    (absence,) = data["absences"]
    assert absence["asked"] == "DKIM keys at acme.test"
    assert absence["evidence"][0] == {
        "name": "_domainkey.acme.test",
        "rtype": "TXT",
        "value": "no such name",
        "checked_at": CHECKED.isoformat(),
    }
    assert {c["where"]: c["denial"] for c in data["checked"]} == {"acme.test": "classic"}


async def test_text_and_markdown_show_checked_and_not_there(offline: httpx.AsyncClient) -> None:
    result = await map_domain(
        "acme.test", checked_at=CHECKED, resolver=Zone(), http=offline, use_web=False
    )
    page = markdown.render(result)
    assert "## Checked and not there" in page
    assert "- DKIM keys at acme.test: no selectors exist" in page
    assert "  - `_domainkey.acme.test TXT no such name`" in page
    console = Console(record=True, width=400)
    text.render(result, console)
    shown = console.export_text()
    assert "CHECKED AND NOT THERE" in shown
    assert "    _domainkey.acme.test TXT no such name" in shown
