"""The contract: every map validates against sendermap/1's JSON Schema, and the schema names
every value the model can emit, so a new Kind fails here until the schema lists it."""

import enum
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from test_evidence import mapped_map

import sendermap
from sendermap import catalog, model
from sendermap.reconcile import with_claimed

SCHEMA = sendermap.schema()
VALIDATOR = Draft202012Validator(SCHEMA)
CORPUS = sorted((Path(__file__).parent / "corpus").glob("*/expected.json"))
# Enums in model.py that never reach to_dict(), and why.
INTERNAL = {"Outcome": "Read stays inside the engine; setups show what it read"}


def errors(data: Any) -> list[str]:
    return [
        f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in VALIDATOR.iter_errors(data)
    ]


def test_the_schema_is_valid_2020_12() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$id"] == (
        "https://raw.githubusercontent.com/marmot7775/sendermap/main/"
        "sendermap/data/schema/sendermap-1.json"
    )
    assert SCHEMA["properties"]["schema"]["const"] == model.SCHEMA == "sendermap/1"


@pytest.mark.parametrize("case", CORPUS, ids=[p.parent.name for p in CORPUS])
def test_every_corpus_map_validates(case: Path) -> None:
    assert errors(json.loads(case.read_text())) == []


async def test_a_map_that_reaches_every_kind_of_object_validates() -> None:
    result = with_claimed(await mapped_map(), ["Zendesk", "Mailchimp", "Acme Mail"], catalog.load())
    data = json.loads(json.dumps(result.to_dict(), default=str))
    reached = {
        "setups": any(s["setups"] for s in data["services"]),
        "supporting": any(c["supporting"] for s in data["services"] for c in s["claims"]),
        "unknowns": bool(data["unknowns"]),
        "findings": bool(data["findings"]),
        "gaps": bool(data["gaps"]),
        "absences": bool(data["absences"]),
        "checked": bool(data["checked"]),
        "historical": bool(data["historical"]),
        "providers": bool(data["ct"]["providers"]),
        "reconciliation": data["reconciliation"] is not None,
        "reporting": any(s["tier"] is None for s in data["services"]),
    }
    assert all(reached.values()), reached
    assert errors(data) == []


def test_a_map_that_breaks_the_contract_does_not_validate() -> None:
    (case,) = [p for p in CORPUS if p.parent.name == "glossier.com"]
    data = json.loads(case.read_text())
    del data["services"][0]["claims"][0]["evidence"]
    data["schema"] = "sendermap/2"
    assert len(errors(data)) == 2


def test_every_enum_member_in_the_model_is_in_the_schema() -> None:
    enums = {
        name: cls
        for name, cls in vars(model).items()
        if isinstance(cls, type) and issubclass(cls, enum.Enum) and cls.__module__ == model.__name__
    }
    assert set(enums) - set(INTERNAL) <= set(SCHEMA["$defs"])
    for name, cls in enums.items():
        if name in INTERNAL:
            continue
        listed = SCHEMA["$defs"][name]["enum"]
        assert [m.value for m in cls] == listed, f"{name}: the schema lists {listed}"
        assert "must tolerate" in SCHEMA["$defs"][name]["description"]


def test_nothing_in_the_schema_forbids_an_added_field() -> None:
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            assert node.get("additionalProperties", True) is not False
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(SCHEMA)
