"""Rule 7: the same DNS answers give the same map, however the answers are timed and whatever
order a record set comes back in."""

import asyncio
import io
import json
import random
from dataclasses import replace

import httpx
from conftest import CHECKED, Zone
from rich.console import Console

from sendermap import SenderMap, map_domain
from sendermap.dns import Answer
from sendermap.render import markdown, text

KEY = "v=DKIM1; k=rsa; p=" + "A" * 392
RUNS = 20


def busy() -> Zone:
    """A domain whose SPF tree branches, repeats a name, fails a lookup and lists ranges, with
    keys, labels and sending subdomains, so every source has something to order."""
    zone = (
        Zone(failing={"_spf.broken.example.net", "fail.example.net"})
        .add("mixed.test", "MX", "1 aspmx.l.google.com", "5 alt1.aspmx.l.google.com")
        .add(
            "mixed.test",
            "TXT",
            "v=spf1 include:_a.mixed.test include:_b.mixed.test include:_spf.google.com "
            "include:_spf.broken.example.net include:unknown-one.example.net ~all",
            "MS=ms12345678",
        )
        .add(
            "_a.mixed.test",
            "TXT",
            "v=spf1 include:_c.mixed.test include:sendgrid.net ip4:54.240.8.0/21 "
            "include:unknown-two.example.net -all",
        )
        .add(
            "_b.mixed.test",
            "TXT",
            "v=spf1 include:_c.mixed.test include:mailgun.org ip4:198.51.100.0/24 "
            "ip4:203.0.113.7 include:unknown-three.example.net -all",
        )
        .add("_c.mixed.test", "TXT", "v=spf1 include:servers.mcsv.net ip4:192.0.2.0/24 -all")
        .add("amazonses.com", "TXT", "v=spf1 ip4:54.240.0.0/18 -all")
        .add("sendgrid.net", "TXT", "v=spf1 include:fail.example.net ip4:167.89.0.0/17 -all")
        .add("_dmarc.mixed.test", "TXT", "v=DMARC1; p=none; rua=mailto:a@rua.agari.com")
        .add("google._domainkey.mixed.test", "TXT", KEY)
        .add("default._domainkey.mixed.test", "TXT", KEY)
        .alias("k2._domainkey.mixed.test", "dkim2.mcsv.net")
        .add("dkim2.mcsv.net", "TXT", KEY)
        .alias("bounce.mixed.test", "sparkpostmail.com")
        .alias("links.mixed.test", "links.iterable.com")
        .add("email.mixed.test", "TXT", "v=spf1 include:mailgun.org ip4:192.0.2.128/25 ~all")
        .add("email.mixed.test", "MX", "10 mxa.mailgun.org")
        .add("mail.mixed.test", "TXT", "v=spf1 include:sendgrid.net -all")
        .add("*._domainkey.mail.mixed.test", "TXT", KEY)
    )
    for ip, asn, name in (
        ("198.51.100.1", "AS64500", "EXAMPLE-NET - Example, US"),
        ("203.0.113.7", "AS64501", "OTHER-NET - Other, US"),
    ):
        reverse = ".".join(reversed(ip.split(".")))
        zone.add(f"{reverse}.origin.asn.cymru.com", "TXT", f"{asn[2:]} | {ip}/24 | US | arin")
        zone.add(f"{asn}.asn.cymru.com", "TXT", f"{asn[2:]} | US | arin | 2005-01-01 | {name}")
    return zone


class Jittery:
    """The zone's answers, each after a random pause, so concurrent tasks finish in a new
    order on every run."""

    def __init__(self, zone: Zone, seed: int) -> None:
        self.zone, self.random = zone, random.Random(seed)

    async def query(self, name: str, rtype: str) -> Answer:
        await asyncio.sleep(self.random.random() / 500)
        return await self.zone.query(name, rtype)


async def test_the_same_answers_give_the_same_map_however_they_are_timed(
    offline: httpx.AsyncClient,
) -> None:
    maps = [
        await map_domain(
            "mixed.test",
            checked_at=CHECKED,
            resolver=Jittery(busy(), seed),
            http=offline,
            use_web=False,
        )
        for seed in range(RUNS)
    ]
    first = maps[0]
    assert first.services and first.unknowns and first.gaps and first.findings
    outputs = {json.dumps({k: v for k, v in m.to_dict().items() if k != "run"}) for m in maps}
    assert len(outputs) == 1, f"{len(outputs)} different maps from {RUNS} runs"
    assert all(m == first for m in maps)
    assert len({m.run.lookups for m in maps}) == 1


class Shuffled:
    """The zone's answers with every record set in a new random order on every query, as a
    resolver may return them (a record set has no order, RFC 2181 section 5)."""

    def __init__(self, zone: Zone, seed: int) -> None:
        self.zone, self.random = zone, random.Random(seed)

    async def query(self, name: str, rtype: str) -> Answer:
        answer = await self.zone.query(name, rtype)
        records = list(answer.records)
        self.random.shuffle(records)
        return Answer(answer.name, answer.rtype, answer.status, tuple(records), answer.chain)


def shuffleable() -> Zone:
    """The busy domain with more record sets of several records: MX hosts of one service at one
    preference and at several, and TXT sets that hold tokens beside SPF."""
    return (
        busy()
        .add("mixed.test", "MX", "5 alt2.aspmx.l.google.com", "10 alt3.aspmx.l.google.com")
        .add("mixed.test", "TXT", "google-site-verification=abc123", "MS=ms87654321")
        .add("email.mixed.test", "MX", "10 mxb.mailgun.org")
        .add("_dmarc.mixed.test", "TXT", "v=DMARC1; p=none; rua=mailto:b@rua.agari.com")
    )


def views(result: SenderMap) -> tuple[str, ...]:
    """Every view of the map: JSON without the run, the deciding claim of each service, and the
    text and Markdown views with and without every claim. The terminal prints the run's elapsed
    time, which the rule leaves out, so it is set to zero first."""
    result = replace(result, run=replace(result.run, elapsed=0.0))
    data = json.dumps({k: v for k, v in result.to_dict().items() if k != "run"})
    deciding = repr([(s.name, s.decided_by) for s in result.services])
    rendered: list[str] = []
    for evidence in (False, True):
        console = Console(record=True, width=400, file=io.StringIO())
        text.render(result, console, evidence=evidence)
        rendered += [console.export_text(), markdown.render(result, evidence=evidence)]
    return (data, deciding, *rendered)


async def test_the_same_record_sets_give_the_same_map_whatever_order_they_come_in(
    offline: httpx.AsyncClient,
) -> None:
    maps = [
        await map_domain(
            "mixed.test",
            checked_at=CHECKED,
            resolver=Shuffled(shuffleable(), seed),
            http=offline,
            use_web=False,
        )
        for seed in range(RUNS)
    ]
    first = maps[0]
    google = next(s for s in first.services if s.name == "Google Workspace")
    assert len([c for c in google.claims if c.evidence.rtype == "MX"]) == 4
    outputs = {views(m) for m in maps}
    assert len(outputs) == 1, f"{len(outputs)} different maps from {RUNS} runs"
    assert all(m == first for m in maps)
