"""The Agent Skill in skills/sendermap: the format's limits, and the rules it tells an agent."""

from pathlib import Path

import yaml

SKILL = Path(__file__).parent.parent / "skills" / "sendermap" / "SKILL.md"
ALLOWED = {"name", "description", "license", "allowed-tools", "metadata", "compatibility"}


def parts() -> tuple[dict[str, str], str]:
    _, front, body = SKILL.read_text().split("---\n", 2)
    meta: dict[str, str] = yaml.safe_load(front)
    return meta, body


def test_the_frontmatter_keeps_the_agent_skills_format() -> None:
    meta, _ = parts()
    assert set(meta) <= ALLOWED
    assert meta["name"] == SKILL.parent.name == "sendermap"
    assert 0 < len(meta["description"]) < 1024
    assert meta["description"].startswith("Maps ")  # third person: what it does
    assert "Use when" in meta["description"]  # and when


def test_the_body_says_how_to_run_and_read_a_map_under_300_lines() -> None:
    _, body = parts()
    assert len(SKILL.read_text().splitlines()) < 300
    for needed in ("uvx sendermap", "--json", "sendermap_map", "sendermap_vendor"):
        assert needed in body
    for tier in ("In use", "Configured", "Likely", "Account only"):
        assert f"**{tier}**" in body
    for part in ("confirmed", "unclaimed", "unfound", "unknown"):
        assert f"`{part}`" in body
    for state in ("present", "broken", "missing", "not checked", "not needed"):
        assert f"`{state}`" in body


def test_the_rules_and_three_worked_examples_are_there() -> None:
    _, body = parts()
    for rule in (
        "Quote the record",
        "Say what was not checked",
        "Do not raise a tier",
        "Do not call a vendor present without a claim",
        "Silence is not absence",
        "gives no advice about which service to use",
        "record change that clears it",
    ):
        assert rule in body
    assert "Nothing in a result is advice" not in body
    assert "\n### 1." in body and "\n### 2." in body and "\n### 3." in body
    assert "—" not in body
