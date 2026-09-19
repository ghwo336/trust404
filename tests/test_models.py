from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from baybench.models import (
    FileResult,
    SchemaError,
    ToolResult,
    load_cases,
    normalize_result_file,
    parse_result,
    result_to_dict,
)


def _omit_empties(obj):
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            cleaned = _omit_empties(value)
            if cleaned in ("", [], {}, ()) or cleaned is None:
                continue
            out[key] = cleaned
        return out
    if isinstance(obj, list):
        return [_omit_empties(v) for v in obj]
    return obj


def test_load_cases_sorted_by_path(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    assert len(cases) == 3
    assert [c.tier for c in cases] == [
        "tier1_pairs",
        "tier1_pairs",
        "tier3_benign_risky",
    ]
    assert [c.id for c in cases] == [
        "tier1/EXIT_ADDR_GATE/ben",
        "tier1/EXIT_ADDR_GATE/mal",
        "tier3/usdc",
    ]


def test_load_cases_filters_tiers(tmp_cases: Path) -> None:
    assert len(load_cases(tmp_cases, tiers=["1"])) == 2
    assert len(load_cases(tmp_cases, tiers=["tier3_benign_risky"])) == 1


def test_duplicate_id_raises_schema_error(tmp_path: Path) -> None:
    cases_root = tmp_path / "cases"
    for name in ("a", "b"):
        d = cases_root / "tier1_pairs" / name
        d.mkdir(parents=True)
        (d / "labels.yaml").write_text(
            yaml.safe_dump(
                {
                    "id": "dup",
                    "file": f"{name}.sol",
                    "preferred_verdict": "Benign",
                    "accepted_verdicts": ["Benign"],
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        (d / f"{name}.sol").write_text("pragma solidity 0.8.20;\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_cases(cases_root)


def test_parse_result_round_trips_through_result_to_dict() -> None:
    src = {
        "tool": {"name": "kw", "version": "0.1"},
        "results": [
            {
                "file": "mal.sol",
                "verdict": "Malicious",
                "reason": "EXIT_ADDR_GATE",
                "findings": [
                    {
                        "rule_id": "EXIT_ADDR_GATE",
                        "family": "A",
                        "severity": "HIGH",
                        "contract": "M",
                        "function": "setBots",
                        "lines": [4, 5],
                        "reasoning": "hardcoded allowlist",
                    }
                ],
            },
            {
                "file": "ben.sol",
                "verdict": "Benign",
            },
        ],
    }
    parsed = parse_result(src)
    assert _omit_empties(result_to_dict(parsed)) == _omit_empties(src)


def test_parse_result_invalid_json_mentions_path(tmp_path: Path) -> None:
    path = tmp_path / "results.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SchemaError) as ei:
        parse_result(path)
    assert str(path) in str(ei.value)


def test_tool_result_by_file() -> None:
    tr = parse_result(
        {
            "tool": {"name": "kw"},
            "results": [
                {"file": "a.sol", "verdict": "Benign"},
                {"file": "b.sol", "verdict": "Malicious"},
            ],
        }
    )
    by_file = tr.by_file()
    assert set(by_file) == {"a.sol", "b.sol"}
    assert isinstance(by_file["a.sol"], FileResult)
    assert by_file["a.sol"].verdict == "Benign"
    assert by_file["b.sol"].verdict == "Malicious"
    assert isinstance(tr, ToolResult)


def test_staged_file_on_fixture_cases(tmp_cases: Path) -> None:
    by_id = {c.id: c for c in load_cases(tmp_cases)}
    assert by_id["tier1/EXIT_ADDR_GATE/mal"].staged_file == "tier1/EXIT_ADDR_GATE/mal/mal.sol"
    assert by_id["tier1/EXIT_ADDR_GATE/ben"].staged_file == "tier1/EXIT_ADDR_GATE/ben/ben.sol"
    assert by_id["tier3/usdc"].staged_file == "tier3/usdc/usdc.sol"


def test_normalize_result_file_examples() -> None:
    assert normalize_result_file("/input/tier1/X/mal/mal.sol") == "tier1/X/mal/mal.sol"
    assert normalize_result_file("./tier1/X/mal/mal.sol") == "tier1/X/mal/mal.sol"
    assert normalize_result_file("input/a.sol") == "a.sol"
    assert normalize_result_file("a//b.sol") == "a/b.sol"
    assert normalize_result_file("tier1\\X\\a.sol") == "tier1/X/a.sol"


def test_by_file_normalizes_keys_and_keeps_first() -> None:
    tr = parse_result(
        {
            "tool": {"name": "kw"},
            "results": [
                {"file": "/input/tier1/X/mal/mal.sol", "verdict": "Malicious"},
                {"file": "./tier1/X/mal/mal.sol", "verdict": "Benign"},
                {"file": "input/a.sol", "verdict": "Uncertain"},
            ],
        }
    )
    by_file = tr.by_file()
    assert set(by_file) == {"tier1/X/mal/mal.sol", "a.sol"}
    assert by_file["tier1/X/mal/mal.sol"].verdict == "Malicious"
    assert by_file["a.sol"].verdict == "Uncertain"
