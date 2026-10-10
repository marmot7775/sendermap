"""Rule 7: the same DNS answers give the same map, however the answers are timed."""

import asyncio
import json
import random

import httpx
from conftest import CHECKED, Zone

from sendermap import map_domain
from sendermap.dns import Answer

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
