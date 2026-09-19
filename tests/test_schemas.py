from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jsonschema.validators import Draft202012Validator

from baybench.models import SchemaError, load_case, load_schema, validate_against


VALID_RESULT = {
    "tool": {"name": "t", "version": "1.0"},
    "results": [
        {
            "file": "x.sol",
            "verdict": "Malicious",
            "reason": "hit",
            "findings": [
                {
                    "rule_id": "EXIT_ADDR_GATE",
                    "family": "A",
                    "severity": "HIGH",
                    "contract": "M",
                    "function": "setBots",
                    "lines": [10, 11],
                    "reasoning": "addr gate",
                }
            ],
        }
    ],
}


def test_schemas_are_valid_draft_2020_12_metaschemas() -> None:
    for name in ("result", "case"):
        schema = load_schema(name)
        Draft202012Validator.check_schema(schema)


def test_valid_result_passes_validate_against() -> None:
    validate_against("result", VALID_RESULT)


def test_result_with_bad_verdict_raises_schema_error() -> None:
    bad = {
        "tool": {"name": "t"},
        "results": [{"file": "x.sol", "verdict": "Bad"}],
    }
    with pytest.raises(SchemaError) as ei:
        validate_against("result", bad)
    assert "verdict" in str(ei.value)


def test_result_with_unknown_top_level_key_raises_schema_error() -> None:
    bad = {**VALID_RESULT, "extra": True}
    with pytest.raises(SchemaError):
        validate_against("result", bad)


def test_finding_missing_family_raises_schema_error() -> None:
    bad = {
        "tool": {"name": "t"},
        "results": [
            {
                "file": "x.sol",
                "verdict": "Malicious",
                "findings": [
                    {"rule_id": "EXIT_ADDR_GATE", "severity": "HIGH"},
                ],
            }
        ],
    }
    with pytest.raises(SchemaError) as ei:
        validate_against("result", bad)
    assert "family" in str(ei.value)


def test_preferred_verdict_not_in_accepted_raises_via_load_case(tmp_path: Path) -> None:
    cases_root = tmp_path / "cases"
    case_dir = cases_root / "tier1_pairs" / "X" / "mal"
    case_dir.mkdir(parents=True)
    labels = case_dir / "labels.yaml"
    labels.write_text(
        yaml.safe_dump(
            {
                "id": "tier1/X/mal",
                "file": "mal.sol",
                "preferred_verdict": "Malicious",
                "accepted_verdicts": ["Benign"],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (case_dir / "mal.sol").write_text("pragma solidity 0.8.20;\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_case(labels, cases_root)


def test_solc_bad_pattern_raises_schema_error() -> None:
    labels = {
        "id": "tier1/X/mal",
        "file": "mal.sol",
        "preferred_verdict": "Malicious",
        "accepted_verdicts": ["Malicious"],
        "solc": "0.8",
    }
    with pytest.raises(SchemaError):
        validate_against("case", labels)
