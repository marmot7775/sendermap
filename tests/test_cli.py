"""The command line for scripts and agents: its exit codes, --output, and a stderr that stays
quiet when it is not a terminal."""

import json
from pathlib import Path

import pytest
from conftest import Zone

from sendermap import cli

OFFLINE = ["--no-web", "--no-subdomains"]
MX = "0 example-test.mail.protection.outlook.com"


def zone(**failing: bool) -> Zone:
    z = Zone(failing={"example.test"} if failing.get("all") else set())
    z.add("example.test", "MX", MX).add(
        "example.test", "TXT", "v=spf1 include:spf.protection.outlook.com -all"
    )
    if failing.get("txt"):
        z.timeouts.add(("example.test", "TXT"))
    return z


@pytest.fixture
def resolver(monkeypatch: pytest.MonkeyPatch) -> list[Zone]:
    """The CLI's resolver replaced by the fake zone the test puts first in the list."""
    zones: list[Zone] = [zone()]
    monkeypatch.setattr(cli, "SystemResolver", lambda: zones[0])
    return zones


def test_a_map_exits_0_and_writes_only_the_map(
    resolver: list[Zone], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["example.test", "--json", *OFFLINE]) == cli.MAPPED == 0
    out, err = capsys.readouterr()
    assert json.loads(out)["domain"] == "example.test"
    assert err == ""  # no spinner when stderr is not a terminal


@pytest.mark.parametrize("domain", ["not a domain", "nodot", ""])
def test_a_bad_domain_exits_2(
    resolver: list[Zone], capsys: pytest.CaptureFixture[str], domain: str
) -> None:
    assert cli.main([domain, *OFFLINE]) == cli.BAD_INPUT == 2
    out, err = capsys.readouterr()
    assert out == "" and err.startswith("sendermap: not a domain")


def test_an_unknown_flag_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(["example.test", "--no-such-flag"])
    assert stopped.value.code == 2


def test_an_output_that_cannot_be_written_exits_2(
    resolver: list[Zone], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "missing" / "map.json"
    assert cli.main(["example.test", "--json", "--output", str(target), *OFFLINE]) == 2
    assert "cannot write" in capsys.readouterr().err


def test_unreadable_own_records_exit_3_with_no_map(
    resolver: list[Zone], capsys: pytest.CaptureFixture[str]
) -> None:
    resolver[0] = zone(all=True)
    assert cli.main(["example.test", "--json", *OFFLINE]) == cli.UNREADABLE == 3
    out, err = capsys.readouterr()
    assert out == ""
    assert err == (
        "sendermap: no map: example.test's own records could not be read "
        "(SPF: TXT at example.test: lookup failed; mail servers: MX at example.test: "
        "lookup failed)\n"
    )


def test_one_unreadable_record_still_maps(
    resolver: list[Zone], capsys: pytest.CaptureFixture[str]
) -> None:
    resolver[0] = zone(txt=True)
    assert cli.main(["example.test", "--json", *OFFLINE]) == 0
    data = json.loads(capsys.readouterr().out)
    assert any(g["asked"] == "SPF: TXT at example.test" for g in data["gaps"])


@pytest.mark.parametrize("fmt", ["--json", "--markdown", None])
def test_output_writes_the_chosen_format_to_the_file(
    resolver: list[Zone], tmp_path: Path, capsys: pytest.CaptureFixture[str], fmt: str | None
) -> None:
    target = tmp_path / "map.out"
    flags = [fmt] if fmt else []
    assert cli.main(["example.test", *flags, "--output", str(target), *OFFLINE]) == 0
    assert capsys.readouterr() == ("", "")
    written = target.read_text(encoding="utf-8")
    if fmt == "--json":
        assert json.loads(written)["schema"] == "sendermap/1"
    elif fmt == "--markdown":
        assert written.startswith("#") and "Microsoft 365" in written
    else:
        assert "Microsoft 365" in written and "\x1b[" not in written  # no terminal codes


def test_help_explains_every_flag_and_the_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    shown = capsys.readouterr().out
    for flag in ("--json", "--markdown", "--output", "--evidence", "--no-web", "--doh", "--ct"):
        assert flag in shown
    assert "exit codes:" in shown and "  3  no map" in shown
