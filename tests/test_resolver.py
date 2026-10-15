"""Which resolver answered: every map names it in its run and its views, and two maps over the
same answers from different resolvers are still the same map."""

import json
from dataclasses import replace
from pathlib import Path

import httpx
import jsonschema
import pytest
from conftest import CHECKED, Zone
from rich.console import Console
from test_determinism import busy

import sendermap
from sendermap import cli, map_domain
from sendermap.dns import DohResolver, SystemResolver, parse_doh
from sendermap.render import markdown, resolver_words, text
from sendermap.testing import Case, RecordingResolver, replay


class Named:
    """The busy zone under another resolver's name."""

    def __init__(self, zone: Zone, name: str) -> None:
        self.zone, self.name = zone, name

    async def query(self, name: str, rtype: str) -> sendermap.dns.Answer:
        return await self.zone.query(name, rtype)


async def busy_map(resolver_name: str, offline: httpx.AsyncClient) -> sendermap.SenderMap:
    return await map_domain(
        "mixed.test",
        checked_at=CHECKED,
        resolver=Named(busy(), resolver_name),
        http=offline,
        use_web=False,
    )


def test_each_resolver_says_what_it_is() -> None:
    assert SystemResolver().name == "system"
    client = httpx.AsyncClient()
    assert DohResolver(client).name == "doh cloudflare"
    assert DohResolver(client, DohResolver.GOOGLE).name == "doh google"
    assert DohResolver(client, "https://doh.example.test/dns-query").name == "doh doh.example.test"


async def test_the_run_names_the_resolver_and_the_map_ignores_it(
    offline: httpx.AsyncClient,
) -> None:
    cloudflare = await busy_map("doh cloudflare", offline)
    google = await busy_map("doh google", offline)
    assert cloudflare.run.resolver == "doh cloudflare"
    assert google.run.resolver == "doh google"
    assert cloudflare == google  # Run compares as nothing
    assert cloudflare.to_dict()["run"]["resolver"] == "doh cloudflare"
    jsonschema.validate(json.loads(json.dumps(cloudflare.to_dict())), sendermap.schema())


async def test_the_views_name_the_resolver(offline: httpx.AsyncClient) -> None:
    result = await busy_map("doh cloudflare", offline)
    result = replace(result, run=replace(result.run, lookups=638, elapsed=11.2))
    assert "(638 lookups over Cloudflare DNS over HTTPS)." in markdown.render(result)
    console = Console(record=True, width=200)
    text.render(result, console)
    assert "638 lookups in 11.2 s over Cloudflare DNS over HTTPS" in console.export_text()
    script = (Path(sendermap.__file__).parent / "web" / "static" / "app.js").read_text()
    assert "over ${resolverWords(map.run.resolver)}" in script
    assert '"doh google": "Google DNS over HTTPS"' in script


def test_the_schema_gains_resolver_as_an_optional_string() -> None:
    run = sendermap.schema()["$defs"]["Run"]
    assert run["properties"]["resolver"]["type"] == "string"
    assert run["required"] == ["checked_at"]


async def test_a_replay_names_the_resolver_the_recording_did(tmp_path: Path) -> None:
    recorder = RecordingResolver(Named(busy(), "doh google"))
    live = await map_domain(
        "mixed.test", checked_at=CHECKED, resolver=recorder, use_web=False, use_subdomains=False
    )
    recorder.save(tmp_path / "dns.json")
    case = Case("mixed.test", CHECKED, False, False, recorder.name)
    (tmp_path / "case.json").write_text(json.dumps(case.to_dict()))
    replayed = await replay(tmp_path)
    assert live.run.resolver == replayed.map.run.resolver == "doh google"


def test_every_corpus_case_names_how_it_was_recorded() -> None:
    corpus = Path(__file__).parent / "corpus"
    for directory in sorted(p for p in corpus.iterdir() if p.is_dir()):
        case = Case.load(directory)
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        assert expected["run"]["resolver"] == case.resolver, directory.name


def test_the_cli_names_the_resolver_it_built(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--doh asks Cloudflare's JSON API, here answered offline; without it, the system resolver."""

    def doh(request: httpx.Request) -> httpx.Response:
        name, rtype = request.url.params["name"], request.url.params["type"]
        if (name, rtype) == ("example.test", "MX"):
            answer = [{"name": name, "type": 15, "data": "0 mx.example.test."}]
            return httpx.Response(200, json={"Status": 0, "Answer": answer})
        return httpx.Response(200, json={"Status": 3})

    monkeypatch.setattr(
        cli, "doh_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(doh))
    )
    assert cli.main(["example.test", "--json", "--doh", "--no-web", "--no-subdomains"]) == 0
    assert json.loads(capsys.readouterr().out)["run"]["resolver"] == "doh cloudflare"

    system = Zone().add("example.test", "MX", "0 mx.example.test")
    monkeypatch.setattr(system, "name", SystemResolver.name)
    monkeypatch.setattr(cli, "SystemResolver", lambda: system)
    assert cli.main(["example.test", "--json", "--no-web", "--no-subdomains"]) == 0
    assert json.loads(capsys.readouterr().out)["run"]["resolver"] == "system"


def test_a_doh_server_failure_is_marked_as_the_domains() -> None:
    assert parse_doh("lame.example.com", "TXT", {"Status": 2}).servfail
    assert not parse_doh("odd.example.com", "TXT", {"Status": 5}).servfail


@pytest.mark.parametrize(
    ("name", "words"),
    [
        ("system", "the system resolver"),
        ("doh google", "Google DNS over HTTPS"),
        ("doh dns.example", "DNS over HTTPS at dns.example"),
        ("fake zone", "fake zone"),
    ],
)
def test_a_resolver_is_named_as_a_reader_says_it(name: str, words: str) -> None:
    assert resolver_words(name) == words
