"""tools/record_corpus.py --recheck: a recorded case mapped live again, compared without
checked_at, recorded outside the corpus, and drift reported rather than failed."""

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import httpx
import pytest
from conftest import Zone

from sendermap.testing import RecordingTransport

LATER = datetime(2026, 10, 19, 10, 0, tzinfo=UTC)


def load_tool() -> ModuleType:
    path = Path(__file__).parent.parent / "tools" / "record_corpus.py"
    spec = importlib.util.spec_from_file_location("record_corpus", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_checked_at_and_order_are_not_drift_and_a_changed_answer_is() -> None:
    tool = load_tool()
    expected = {"run": {"checked_at": "2026-10-11T00:00:00+00:00"}, "mx": ["10 a.test"]}
    later = {"run": {"checked_at": "2026-10-19T10:00:00+00:00"}, "mx": ["10 a.test"]}
    assert tool.drift(expected, later) == []
    rotated = {"mx": ["20 b.test", "10 a.test"]}
    assert tool.drift({"mx": ["10 a.test", "20 b.test"]}, rotated) == []  # an RRset has no order

    moved = {"run": {"checked_at": "2026-10-19T10:00:00+00:00"}, "mx": ["10 b.test"]}
    diff = tool.drift(expected, moved)
    assert diff[:2] == ["--- expected.json", "+++ live"]
    assert '-  "10 a.test"' in diff
    assert '+  "10 b.test"' in diff
    assert not any("checked_at" in line for line in diff)


async def test_a_recheck_records_outside_the_corpus_and_reports_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = load_tool()
    corpus, out = tmp_path / "corpus", tmp_path / "out"
    zone = Zone().add("shop.test", "MX", "10 aspmx.l.google.com")
    monkeypatch.setattr(tool, "CORPUS", corpus)
    monkeypatch.setattr(tool, "SystemResolver", lambda: zone)
    monkeypatch.setattr(
        tool,
        "RecordingTransport",
        lambda: RecordingTransport(httpx.MockTransport(lambda _: httpx.Response(404))),
    )
    await tool.record("shop.test", use_web=False)
    case = corpus / "shop.test"
    recorded = {p.name: p.read_bytes() for p in case.iterdir()}

    monkeypatch.setattr(tool, "_now", lambda: LATER)
    report = await tool.recheck("shop.test", out)
    assert report == "### shop.test\n\nNo drift: the live map is the recorded one.\n"
    assert (out / "shop.test" / "dns.json").exists()
    fresh = json.loads((out / "shop.test" / "case.json").read_text())
    assert fresh["checked_at"] == LATER.isoformat()
    assert fresh["use_web"] is False and fresh["use_subdomains"] is True

    zone.add("shop.test", "MX", "20 mx.other.test")
    report = await tool.recheck("shop.test", out)
    assert report.startswith("### shop.test\n\nDrifted (")
    assert any(line.startswith("+") and "mx.other.test" in line for line in report.splitlines())
    assert {p.name: p.read_bytes() for p in case.iterdir()} == recorded  # the corpus is untouched
