"""The DKIM sweep's opt-in early stop (dns-audit issue 282).

By default every selector is asked. With stop_early, the names of services the domain's SPF, MX
and CNAMEs already name go first, with the names any domain is asked. Once every service the
sending evidence names has a key, the rest is not asked, and the names left are recorded as
skipped with a gap of their own, so the map never says no key is there.
"""

from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone

from sendermap import catalog, map_domain
from sendermap.dns import Answer
from sendermap.model import Claim, Evidence, GapKind, Kind, SenderMap, State
from sendermap.sources import CANARY, dkim
from sendermap.testing import Case, ReplayResolver, ReplayTransport

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392
DOMAIN = "plan.test"
CORPUS = sorted(
    p for p in (Path(__file__).parent / "corpus").iterdir() if (p / "case.json").exists()
)


def google(domain: str = DOMAIN) -> Zone:
    """Google Workspace in MX and SPF, signing with its google key."""
    return (
        Zone()
        .add(domain, "MX", "1 smtp.google.com")
        .add(domain, "TXT", "v=spf1 include:_spf.google.com -all")
        .add(f"google._domainkey.{domain}", "TXT", KEY)
        .selectors_exist(domain)
    )


async def mapped(zone: Any, http: httpx.AsyncClient, *, stop: bool = False) -> SenderMap:
    return await map_domain(
        DOMAIN,
        checked_at=CHECKED,
        resolver=zone,
        http=http,
        use_web=False,
        use_subdomains=False,
        stop_early=stop,
    )


def probes(zone: Zone, domain: str = DOMAIN) -> list[str]:
    """The selectors asked under _domainkey.<domain>, in order, without the wildcard canary."""
    suffix = f"._domainkey.{domain}"
    return [
        n.removesuffix(suffix)
        for n, t in zone.asked
        if t == "TXT" and n.endswith(suffix) and not n.startswith(CANARY)
    ]


def same_answers(result: SenderMap) -> dict[str, Any]:
    """What a map says about senders: its services, findings and unknowns."""
    data = result.to_dict()
    return {k: data[k] for k in ("services", "findings", "unknowns")}


async def test_a_google_workspace_domain_asks_far_fewer_names_and_maps_the_same(
    offline: httpx.AsyncClient,
) -> None:
    full_zone, zone = google(), google()
    full = await mapped(full_zone, offline)
    early = await mapped(zone, offline, stop=True)
    assert same_answers(early) == same_answers(full)
    before, after = len(probes(full_zone)), len(probes(zone))
    assert after <= before // 2, (before, after)
    assert probes(zone)[0] in ("google", "gapps")
    (stop,) = [g for g in early.gaps if g.kind is GapKind.DKIM_STOPPED]
    (checked,) = [c for c in early.checked if c.where == DOMAIN]
    assert stop.count == len(checked.dkim_skipped) == before - after
    assert set(checked.dkim_skipped).isdisjoint(checked.dkim_selectors)
    assert "the probe stops once each sender has a key" in early.story
    assert not any(g.kind is GapKind.DKIM_STOPPED for g in full.gaps)


async def test_a_domain_with_no_vendor_evidence_runs_the_full_list(
    offline: httpx.AsyncClient,
) -> None:
    def bare() -> Zone:
        return (
            Zone()
            .add(DOMAIN, "MX", "10 mail.plan.test")
            .add(DOMAIN, "TXT", "v=spf1 mx -all")
            .add(f"default._domainkey.{DOMAIN}", "TXT", KEY)
            .selectors_exist(DOMAIN)
        )

    full_zone, zone = bare(), bare()
    full = await mapped(full_zone, offline)
    early = await mapped(zone, offline, stop=True)
    assert sorted(probes(zone)) == sorted(probes(full_zone))
    assert len(probes(zone)) == len(catalog.load().probe_selectors)
    assert same_answers(early) == same_answers(full)
    assert not any(c.dkim_skipped for c in early.checked)


async def test_a_sender_without_a_key_keeps_the_sweep_going(offline: httpx.AsyncClient) -> None:
    # Amazon SES is in SPF and has no key at its name, so the probe cannot stop for it.
    def zone_with_ses() -> Zone:
        zone = google()
        zone.records[(DOMAIN, "TXT")] = [
            "v=spf1 include:_spf.google.com include:amazonses.com -all"
        ]
        return zone

    full_zone, zone = zone_with_ses(), zone_with_ses()
    full = await mapped(full_zone, offline)
    early = await mapped(zone, offline, stop=True)
    assert same_answers(early) == same_answers(full)
    # Google's own names were asked first, as SPF names it, so nothing is left unasked.
    assert sorted(probes(zone)) == sorted(probes(full_zone))
    assert not any(c.dkim_skipped for c in early.checked)
    assert not any(g.kind is GapKind.DKIM_STOPPED for g in early.gaps)


async def test_a_key_under_a_name_the_stop_skipped_is_not_asked_not_absent(
    offline: httpx.AsyncClient,
) -> None:
    # Mailjet signs too, but nothing else in DNS names it: its key is past the early stop.
    zone = google().add(f"mailjet._domainkey.{DOMAIN}", "TXT", KEY)
    full = await mapped(google().add(f"mailjet._domainkey.{DOMAIN}", "TXT", KEY), offline)
    early = await mapped(zone, offline, stop=True)
    assert "Mailjet" in [s.name for s in full.services]
    assert "Mailjet" not in [s.name for s in early.services]
    assert "mailjet" not in probes(zone)
    (checked,) = [c for c in early.checked if c.where == DOMAIN]
    assert "mailjet" in checked.dkim_skipped and "mailjet" not in checked.dkim_selectors
    (stop,) = [g for g in early.gaps if g.kind is GapKind.DKIM_STOPPED]
    assert stop.asked == f"DKIM selectors at {DOMAIN}"
    assert "every service the SPF, MX and CNAMEs" in stop.happened
    # Nothing says no key was found: no absence, and the only gap is the stop's.
    assert not early.absences
    assert [g.kind for g in early.gaps if g.kind in (GapKind.DKIM, GapKind.DKIM_STOPPED)] == [
        GapKind.DKIM_STOPPED
    ]


async def test_a_failed_lookup_stays_probe_incomplete_beside_the_stop(
    offline: httpx.AsyncClient,
) -> None:
    zone = google()
    zone.timeouts.add((f"selector1._domainkey.{DOMAIN}", "TXT"))
    early = await mapped(zone, offline, stop=True)
    kinds = {g.kind: g for g in early.gaps if g.kind in (GapKind.DKIM, GapKind.DKIM_STOPPED)}
    assert set(kinds) == {GapKind.DKIM, GapKind.DKIM_STOPPED}
    assert kinds[GapKind.DKIM].happened == "lookup failed"
    assert "selector1" in kinds[GapKind.DKIM].asked


async def test_a_setup_selector_the_stop_skipped_reads_not_checked(
    offline: httpx.AsyncClient,
) -> None:
    # Mailjet shows only by the network that announces a range in SPF, which is read beside the
    # DKIM probe, not before it: its selector is past the stop, so its setup is not checked.
    zone = google().add(f"mailjet._domainkey.{DOMAIN}", "TXT", KEY)
    zone.records[(DOMAIN, "TXT")] = ["v=spf1 include:_spf.google.com ip4:87.253.232.0/24 -all"]
    zone.add("1.232.253.87.origin.asn.cymru.com", "TXT", "200069 | 87.253.232.0/24 | FR | ripe | x")
    zone.add("as200069.asn.cymru.com", "TXT", "200069 | FR | ripe | 2010-01-01 | MAILJET, FR")
    early = await mapped(zone, offline, stop=True)
    mailjet = next(s for s in early.services if s.name == "Mailjet")
    assert any(c.kind is Kind.SPF_NETWORK for c in mailjet.claims)
    (dkim_item,) = [i for st in mailjet.setups for i in st.items if i.record == "dkim"]
    assert dkim_item.state is State.NOT_CHECKED
    assert "mailjet not asked" in dkim_item.detail and "probe stopped" in dkim_item.detail


def test_the_plan_puts_evidence_first_and_stops_only_when_every_sender_has_a_key() -> None:
    loaded = catalog.load()
    spf = Claim("Mailgun", Kind.SPF_INCLUDE, DOMAIN, Evidence(DOMAIN, "TXT", "x", CHECKED))
    order = dkim.plan(loaded, DOMAIN, loaded.probe_selectors, [spf])
    assert {"mg", "mailgun", "pdk1"} <= set(order.first)
    assert {"google", "selector1", "selector2", "default", "k2", "s1"} <= set(order.first)
    assert "mailjet" in order.rest
    assert order.senders == {"Mailgun"}
    assert order.then({"Mailgun"}) == ()
    assert order.then(set()) == order.rest
    # A service with a key loses its other names, never a name another service also uses.
    assert "gapps" not in order.then({"Google Workspace"})
    assert "mailjet" in order.then({"Google Workspace"})


def test_without_senders_the_plan_never_stops() -> None:
    loaded = catalog.load()
    order = dkim.plan(loaded, DOMAIN, loaded.probe_selectors, [])
    assert order.senders == frozenset()
    assert set(order.then({"Google Workspace", "Microsoft 365"})) == set(order.rest) - {"gapps"}


class Counting:
    def __init__(self, inner: ReplayResolver) -> None:
        self.inner, self.asked = inner, set[str]()

    @property
    def name(self) -> str:
        return self.inner.name

    async def query(self, name: str, rtype: str) -> Answer:
        if rtype == "TXT" and "._domainkey." in name and not name.startswith(CANARY):
            self.asked.add(name)
        return await self.inner.query(name, rtype)


async def replayed(case_dir: Path, *, stop: bool) -> tuple[SenderMap, int]:
    case = Case.load(case_dir)
    resolver = Counting(ReplayResolver(case_dir / "dns.json", case.resolver))
    pages = case_dir / "http.json"
    transport = ReplayTransport(pages) if pages.exists() else ReplayTransport.empty()
    async with httpx.AsyncClient(transport=transport) as http:
        result = await map_domain(
            case.domain,
            checked_at=case.checked_at,
            resolver=resolver,
            http=http,
            use_web=case.use_web,
            use_subdomains=case.use_subdomains,
            use_ct=False,
            stop_early=stop,
        )
    return replace(result, story=""), len(resolver.asked)


@pytest.mark.parametrize("case", CORPUS, ids=[c.name for c in CORPUS])
async def test_a_recorded_domain_names_the_same_senders_either_way(case: Path) -> None:
    full, asked_full = await replayed(case, stop=False)
    early, asked_early = await replayed(case, stop=True)
    assert same_answers(early) == same_answers(full)
    assert asked_early <= asked_full


def hubspot_too() -> Zone:
    """Google Workspace in MX and SPF, and a HubSpot key that nothing else in DNS points to."""
    return google().add(f"hs1._domainkey.{DOMAIN}", "TXT", KEY)


async def test_by_default_every_selector_is_asked_and_hs1_is_found(
    offline: httpx.AsyncClient,
) -> None:
    zone = hubspot_too()
    result = await mapped(zone, offline)
    assert set(catalog.load().probe_selectors) <= set(probes(zone))
    hubspot = next(s for s in result.services if s.name == "HubSpot")
    assert any(
        c.kind is Kind.DKIM_NAME and c.evidence.name.startswith("hs1.") for c in hubspot.claims
    )
    assert not any(c.dkim_skipped for c in result.checked)
    assert not any(g.kind is GapKind.DKIM_STOPPED for g in result.gaps)


async def test_the_opt_in_stop_misses_hs1_and_says_it_was_not_asked(
    offline: httpx.AsyncClient,
) -> None:
    zone = hubspot_too()
    early = await mapped(zone, offline, stop=True)
    assert "hs1" not in probes(zone)
    assert "HubSpot" not in [s.name for s in early.services]
    (checked,) = [c for c in early.checked if c.where == DOMAIN]
    assert "hs1" in checked.dkim_skipped


@pytest.mark.parametrize("case", CORPUS, ids=[c.name for c in CORPUS])
async def test_by_default_a_recorded_domain_asks_every_name_once_in_sweep_order(
    case: Path,
) -> None:
    result, _ = await replayed(case, stop=False)
    assert not any(c.dkim_skipped for c in result.checked)
    assert not any(g.kind is GapKind.DKIM_STOPPED for g in result.gaps)
