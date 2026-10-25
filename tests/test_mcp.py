"""The MCP server: both tools called through an in-memory client on the fake zone, the
structured content valid against sendermap/1 in both detail modes, and every text an agent
reads kept under its limit."""

import json
import re
from importlib import resources
from typing import Any

import httpx
import pytest
from conftest import CHECKED, Zone
from jsonschema import Draft202012Validator
from test_evidence import mapped, site

pytest.importorskip("fastmcp")

from fastmcp import Client
from fastmcp.exceptions import ToolError

import sendermap
from sendermap import catalog, cli, mcp_server
from sendermap.engine import Progress, map_domain
from sendermap.model import Finding, Run, SenderMap, Severity
from sendermap.render.view import view

VALIDATOR = Draft202012Validator(sendermap.schema())
CLAIMED = ["Office 365", "Mailchimp", "Acme Mail"]


async def fake(domain: str, options: mcp_server.Options, progress: Progress) -> SenderMap:
    async with httpx.AsyncClient(transport=httpx.MockTransport(site)) as http:
        return await map_domain(
            domain,
            checked_at=CHECKED,
            resolver=mapped(),
            http=http,
            use_web=options.use_web,
            use_subdomains=options.use_subdomains,
            use_ct=options.use_ct,
            progress=progress,
        )


def errors(data: Any) -> list[str]:
    return sorted(e.message for e in VALIDATOR.iter_errors(data))


@pytest.mark.parametrize("detail", ["summary", "full"])
async def test_the_map_tool_returns_valid_sendermap_1_json(detail: str) -> None:
    async with Client(mcp_server.create(fake)) as client:
        result = await client.call_tool(
            "sendermap_map", {"domain": "mapped.test", "claimed": CLAIMED, "detail": detail}
        )
    data = result.structured_content
    assert data is not None
    assert data["schema"] == "sendermap/1"
    assert data["domain"] == "mapped.test"
    assert errors(data) == []
    assert data["reconciliation"]["unknown"] == ["Acme Mail"]


async def test_full_is_to_dict_and_summary_keeps_the_deciding_claim_and_setups() -> None:
    expected = await fake("mapped.test", mcp_server.Options(), _quiet)
    full = mcp_server.structured(expected, "full")
    assert full == json.loads(json.dumps(expected.to_dict(), default=str))
    summary = mcp_server.structured(expected, "summary")
    assert "checked" not in summary
    assert "subdomains_checked" not in summary
    assert full["checked"]
    for service, row in zip(expected.services, summary["services"], strict=True):
        (claim,) = row["claims"]
        assert claim["kind"] == service.decided_by.kind.value
        assert claim["evidence"]["value"] == service.decided_by.evidence.value
        assert len(row["setups"]) == len(service.setups)
    assert any(row["setups"] for row in summary["services"])
    assert len(json.dumps(summary)) < len(json.dumps(full))


async def test_the_text_block_tells_the_story_then_findings_then_claimed() -> None:
    async with Client(mcp_server.create(fake)) as client:
        result = await client.call_tool(
            "sendermap_map", {"domain": "https://mapped.test/", "claimed": CLAIMED}
        )
    (block,) = result.content
    expected = await fake("mapped.test", mcp_server.Options(), _quiet)
    assert expected.story
    assert block.text.startswith(expected.story)
    for finding in view(expected, evidence=False).findings:
        assert f"- {finding.title} ({finding.severity}). {finding.detail}" in block.text
    story_at = block.text.index(expected.story)
    assert story_at < block.text.index("Needs attention:") < block.text.index("Claimed senders:")
    assert 'Microsoft 365, Configured (claimed as "Office 365")' in block.text


async def test_the_claimed_sections_appear_only_when_a_list_is_given() -> None:
    async with Client(mcp_server.create(fake)) as client:
        result = await client.call_tool("sendermap_map", {"domain": "mapped.test"})
    assert "Claimed senders:" not in result.content[0].text
    assert result.structured_content is not None
    assert result.structured_content["reconciliation"] is None


async def test_the_options_reach_the_build() -> None:
    seen: list[mcp_server.Options] = []

    async def build(domain: str, options: mcp_server.Options, progress: Progress) -> SenderMap:
        seen.append(options)
        return await fake(domain, options, progress)

    async with Client(mcp_server.create(build)) as client:
        await client.call_tool(
            "sendermap_map",
            {"domain": "mapped.test", "website": False, "subdomains": False},
        )
        await client.call_tool("sendermap_map", {"domain": "mapped.test", "certificate_log": True})
    assert seen == [
        mcp_server.Options(use_web=False, use_subdomains=False, use_ct=False),
        mcp_server.Options(use_web=True, use_subdomains=True, use_ct=True),
    ]


async def test_progress_from_the_engine_goes_out_as_mcp_progress() -> None:
    steps: list[tuple[float, str | None]] = []

    async def handler(progress: float, total: float | None, message: str | None) -> None:
        steps.append((progress, message))

    async with Client(mcp_server.create(fake), progress_handler=handler) as client:
        await client.call_tool("sendermap_map", {"domain": "mapped.test"})
    assert len(steps) > 3
    assert [p for p, _ in steps] == list(range(1, len(steps) + 1))
    assert all(message for _, message in steps)


async def test_a_bad_domain_and_an_unreadable_domain_are_tool_errors() -> None:
    async def failing(domain: str, options: mcp_server.Options, progress: Progress) -> SenderMap:
        return await map_domain(
            domain,
            checked_at=CHECKED,
            resolver=Zone(failing={"down.test"}),
            use_web=False,
            use_subdomains=False,
        )

    async with Client(mcp_server.create(failing)) as client:
        with pytest.raises(ToolError, match="does not look like a domain"):
            await client.call_tool("sendermap_map", {"domain": "not a domain"})
        with pytest.raises(ToolError, match="own records could not be read"):
            await client.call_tool("sendermap_map", {"domain": "down.test"})


async def test_the_vendor_tool_returns_the_block_with_its_proofs() -> None:
    raw = json.loads(resources.files("sendermap").joinpath("data/vendors.json").read_text())
    async with Client(mcp_server.create(fake)) as client:
        result = await client.call_tool("sendermap_vendor", {"name": "office 365"})
        with pytest.raises(ToolError, match="No vendor goes by"):
            await client.call_tool("sendermap_vendor", {"name": "Mailchimps"})
    block = json.loads(result.content[0].text)
    assert result.structured_content == block
    assert list(block)[:3] == ["name", "category", "aliases"]
    assert block["name"] == "Microsoft 365"
    expected = raw["vendors"]["Microsoft 365"]
    assert {k: v for k, v in block.items() if k != "name"} == expected
    assert block["setup"] and block["sending_ip"]
    assert all(entry["proof"] for entry in block["spf_includes"])


async def test_both_resources_are_served() -> None:
    async with Client(mcp_server.create(fake)) as client:
        listed = {str(r.uri): r for r in await client.list_resources()}
        assert set(listed) == {mcp_server.SCHEMA_URI, mcp_server.VENDORS_URI}
        (schema,) = await client.read_resource(mcp_server.SCHEMA_URI)
        (vendors,) = await client.read_resource(mcp_server.VENDORS_URI)
    assert json.loads(schema.text) == sendermap.schema()
    rows = json.loads(vendors.text)
    assert [r["name"] for r in rows] == list(catalog.load().services)
    assert all(set(r) == {"name", "category", "aliases"} for r in rows)


async def test_the_tools_declare_what_an_agent_needs_under_the_limits() -> None:
    async with Client(mcp_server.create(fake)) as client:
        tools = {t.name: t for t in await client.list_tools()}
        instructions = client.instructions
    assert set(tools) == {"sendermap_map", "sendermap_vendor"}
    assert instructions == mcp_server.INSTRUCTIONS
    assert len(instructions) < 2048
    for tool in tools.values():
        assert len(tool.name) < 64
        assert tool.title
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.description
        assert 3 <= len(_sentences(tool.description)) <= 4, tool.name
    assert tools["sendermap_map"].output_schema is not None
    assert tools["sendermap_map"].output_schema["title"] == sendermap.schema()["title"]
    words = list(tools["sendermap_map"].input_schema["properties"])
    assert words == ["domain", "claimed", "website", "subdomains", "certificate_log", "detail"]
    for name in words:  # the description says what each parameter means
        assert name in tools["sendermap_map"].description


def test_the_server_text_names_the_tiers_and_the_advice_it_does_not_give() -> None:
    for tier in ("In use", "Configured", "Likely", "Account only"):
        assert f"- {tier}:" in mcp_server.INSTRUCTIONS
    assert "Silence is not absence" in mcp_server.INSTRUCTIONS
    assert "gives no advice about which service to use" in mcp_server.INSTRUCTIONS
    assert "the record change that clears it" in mcp_server.INSTRUCTIONS
    assert "Nothing in a result is advice" not in mcp_server.INSTRUCTIONS
    for text in (
        mcp_server.INSTRUCTIONS,
        mcp_server.MAP_DESCRIPTION,
        mcp_server.VENDOR_DESCRIPTION,
    ):
        assert not re.search(r"consult|hire|contact us|dns-audit", text, re.IGNORECASE)
        assert "—" not in text


def test_the_mcp_command_needs_no_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    served: list[bool] = []
    monkeypatch.setattr(mcp_server, "serve", lambda: served.append(True))
    assert cli.main(["mcp"]) == cli.MAPPED
    assert served == [True]


def _sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s]


async def _quiet(_: str) -> None:
    return None


def test_the_text_block_says_short_keys_at_one_name_once_most_severe_first() -> None:
    warn = "Some receivers already treat 1024-bit RSA keys as weak. Rotate to 2048-bit."
    findings = (
        Finding(Severity.NOTE, "A note", "Said last."),
        Finding(Severity.WARNING, "The s1 key at mapped.test is 1024-bit", warn),
        Finding(Severity.WARNING, "The s2 key at mapped.test is 1024-bit", warn),
        Finding(Severity.RISK, "A risk", "Said first."),
    )
    shown = SenderMap("mapped.test", (), Run(CHECKED, 0.0, 0, "fake zone"), findings=findings)
    lines = mcp_server.text(shown).splitlines()
    assert lines[2:] == [
        "Needs attention:",
        "- A risk (risk). Said first.",
        f"- Two DKIM keys at mapped.test are 1024-bit: s1 and s2 (warning). {warn}",
        "- A note (note). Said last.",
    ]
