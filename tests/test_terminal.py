"""The terminal layout: every column of the glance survives a narrow terminal, the names asked sit
under the count they belong to, and the certificate log section prints when CT ran."""

import io
from pathlib import Path

import httpx
from conftest import CHECKED
from rich.console import Console
from test_ct import DOMAIN, Logs, zone
from test_view import CORPUS, mapped

from sendermap import map_domain
from sendermap.model import SenderMap
from sendermap.render import ct_lines, text, view


def terminal(result: SenderMap, *, width: int = 100, evidence: bool = False) -> list[str]:
    out = io.StringIO()
    text.render(result, Console(file=out, width=width, color_system=None), evidence=evidence)
    return [line.rstrip() for line in out.getvalue().splitlines()]


def section(lines: list[str], title: str) -> list[str]:
    """The lines under one section heading, up to the next blank line."""
    start = lines.index(title) + 1
    end = next((i for i in range(start, len(lines)) if not lines[i].strip()), len(lines))
    return lines[start:end]


async def test_the_glance_keeps_its_marker_and_setup_columns_at_80_columns() -> None:
    # A long name once kept its full width, and rich took the room from the marker and setup
    # columns until they showed nothing.
    result = await mapped(CORPUS / "casper.com")
    services = view(result, evidence=False).services
    glance = section(terminal(result, width=80), "AT A GLANCE")
    rows = [line for line in glance if line.lstrip()[:1] in "●◐○"]
    assert len(rows) == len(services)
    for service in services:
        words, _ = service.glance
        if words:
            assert any(words.split()[0] in line for line in glance), service.name
    assert any("✓ setup complete" in line for line in rows)


async def test_names_asked_sit_under_the_count_they_belong_to() -> None:
    result = await mapped(CORPUS / "glossier.com")
    asked = view(result, evidence=True).asked
    how = terminal(result, evidence=True)
    how = how[how.index("HOW THIS WAS CHECKED") + 1 :]
    record = next(r for r in asked if r.names)
    count = how.index(f"    {record.where}: {record.counts}")
    heading, _ = record.names[0]
    assert how[count + 1].startswith(f"      {heading}:")
    first_other = next(i for i, line in enumerate(how) if line.startswith("  Not "))
    names = [i for i, line in enumerate(how) if line.startswith("      ")]
    assert names and max(names) < first_other


async def test_the_certificate_logs_print_when_ct_ran(tmp_path: Path) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(Logs())) as http:
        result = await map_domain(
            DOMAIN,
            checked_at=CHECKED,
            resolver=zone(),
            http=http,
            use_web=False,
            use_subdomains=False,
            use_ct=True,
            ct_cache=tmp_path,
        )
    shown = " ".join(" ".join(terminal(result, width=200)).split())
    assert "CERTIFICATE LOGS" in shown
    for line in ct_lines(result):
        assert line in shown
    assert "MX for bounces mxa.mailgun.org" in shown
