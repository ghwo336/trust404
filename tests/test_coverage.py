from __future__ import annotations

from pathlib import Path

import yaml

from baybench.catalog import load_catalog
from baybench.coverage import coverage_report, format_gaps_md, tool_gaps
from baybench.models import load_cases, parse_result


def _write_labels(case_dir: Path, payload: dict) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "labels.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )


def _write_sol(case_dir: Path, filename: str) -> None:
    (case_dir / filename).write_text(
        "pragma solidity 0.8.20; contract C {}\n",
        encoding="utf-8",
    )


def _malicious_result(staged_file: str, rule_id: str, family: str, severity: str = "HIGH"):
    return parse_result(
        {
            "tool": {"name": "kw"},
            "results": [
                {
                    "file": staged_file,
                    "verdict": "Malicious",
                    "findings": [
                        {
                            "rule_id": rule_id,
                            "family": family,
                            "severity": severity,
                        }
                    ],
                }
            ],
        }
    )


def test_coverage_report_fixture_counts(tmp_cases: Path) -> None:
    catalog = load_catalog()
    report = coverage_report(load_cases(tmp_cases), catalog)

    assert report["rules"]["EXIT_ADDR_GATE"]["n_cases"] == 1
    assert "EXIT_ADDR_GATE" not in report["rules_zero_cases"]
    assert "PONZI_SHAPE" in report["rules_zero_cases"]
    assert len(report["rules_zero_cases"]) == 28

    assert report["families"]["A"]["n_cases"] == 1
    assert report["families"]["A"]["n_malicious"] == 1
    assert report["families_zero_cases"] == ["B", "C", "D", "E", "F", "G"]
    assert report["unknown_rule_ids"] == []
    assert report["n_cases"] == 3
    assert report["per_tier"] == {"tier1_pairs": 2, "tier3_benign_risky": 1}


def test_tier1_pairs_and_missing(tmp_cases: Path) -> None:
    report = coverage_report(load_cases(tmp_cases), load_catalog())

    assert report["tier1_pairs"]["EXIT_ADDR_GATE"] == {"malicious": 1, "benign": 1}
    assert "EXIT_ADDR_GATE" not in report["rules_missing_pair"]
    assert "BAL_PRIV_MINT" in report["rules_missing_pair"]
    assert len(report["rules_missing_pair"]) == 28


def test_unknown_rule_ids_and_dirs(tmp_cases: Path) -> None:
    _write_labels(
        tmp_cases / "tier1_pairs" / "NOT_A_RULE" / "mal",
        {
            "id": "tier1/NOT_A_RULE/mal",
            "file": "mal.sol",
            "preferred_verdict": "Malicious",
            "accepted_verdicts": ["Malicious"],
            "expected_rule_ids": ["NOT_A_RULE"],
            "expected_families": ["A"],
        },
    )
    report = coverage_report(load_cases(tmp_cases), load_catalog())
    assert report["unknown_rule_ids"] == ["NOT_A_RULE"]
    assert "NOT_A_RULE" in report["tier1_unknown_rule_dirs"]


def test_tier1_uncertain_mal_leaf_counts_as_pair(tmp_cases: Path) -> None:
    mal_dir = tmp_cases / "tier1_pairs" / "FEE_ADDR_MUTABLE" / "mal"
    _write_labels(
        mal_dir,
        {
            "id": "tier1/FEE_ADDR_MUTABLE/mal",
            "file": "mal.sol",
            "preferred_verdict": "Uncertain",
            "accepted_verdicts": ["Uncertain", "Malicious"],
            "expected_rule_ids": ["FEE_ADDR_MUTABLE"],
            "expected_families": ["C"],
        },
    )
    _write_sol(mal_dir, "mal.sol")
    ben_dir = tmp_cases / "tier1_pairs" / "FEE_ADDR_MUTABLE" / "ben"
    _write_labels(
        ben_dir,
        {
            "id": "tier1/FEE_ADDR_MUTABLE/ben",
            "file": "ben.sol",
            "preferred_verdict": "Benign",
            "accepted_verdicts": ["Benign"],
        },
    )
    _write_sol(ben_dir, "ben.sol")

    report = coverage_report(load_cases(tmp_cases), load_catalog())
    assert report["tier1_pairs"]["FEE_ADDR_MUTABLE"] == {"malicious": 1, "benign": 1}
    assert "FEE_ADDR_MUTABLE" not in report["rules_missing_pair"]
    assert report["tier1_pairs"]["EXIT_ADDR_GATE"] == {"malicious": 1, "benign": 1}
    assert "EXIT_ADDR_GATE" not in report["rules_missing_pair"]


def test_tier1_harness_dir_skipped(tmp_cases: Path) -> None:
    harness_dir = tmp_cases / "tier1_pairs" / "_harness" / "compile_fail"
    _write_labels(
        harness_dir,
        {
            "id": "tier1/_harness/compile_fail",
            "file": "compile_fail.sol",
            "preferred_verdict": "Uncertain",
            "accepted_verdicts": ["Uncertain"],
            "notes": "expect_compile_fail",
        },
    )
    _write_sol(harness_dir, "compile_fail.sol")

    report = coverage_report(load_cases(tmp_cases), load_catalog())
    assert "_harness" not in report["tier1_unknown_rule_dirs"]
    assert "_harness" not in report["tier1_pairs"]
    assert "_harness" not in report["rules_missing_pair"]
    assert "EXIT_ADDR_GATE" not in report["rules_missing_pair"]
    assert len(report["rules_missing_pair"]) == 28


def test_tool_gaps_malicious_only(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    mal = next(c for c in cases if c.id == "tier1/EXIT_ADDR_GATE/mal")

    hit = _malicious_result(mal.staged_file, "EXIT_ADDR_GATE", "A")
    assert tool_gaps(cases, hit) == []

    wrong_rule = _malicious_result(mal.staged_file, "PRIV_ROLE", "A", severity="INFO")
    gaps = tool_gaps(cases, wrong_rule)
    assert len(gaps) == 1
    assert gaps[0]["id"] == mal.id
    assert gaps[0]["reason"] == "no_expected_rule"
    assert gaps[0]["fired_rule_ids"] == ["PRIV_ROLE"]

    missing = parse_result({"tool": {"name": "kw"}, "results": []})
    gaps = tool_gaps(cases, missing)
    assert len(gaps) == 1
    assert gaps[0]["id"] == mal.id
    assert gaps[0]["reason"] == "no_result"
    assert gaps[0]["verdict"] is None
    assert all(g["id"] != "tier1/EXIT_ADDR_GATE/ben" for g in gaps)
    assert all(g["id"] != "tier3/usdc" for g in gaps)
    assert {c.id for c in cases if c.is_benign} == {
        "tier1/EXIT_ADDR_GATE/ben",
        "tier3/usdc",
    }


def test_tool_gaps_family_fallback(tmp_cases: Path) -> None:
    _write_labels(
        tmp_cases / "tier2_realworld" / "x",
        {
            "id": "tier2/x",
            "file": "x.sol",
            "preferred_verdict": "Malicious",
            "accepted_verdicts": ["Malicious"],
            "expected_families": ["A"],
        },
    )
    cases = load_cases(tmp_cases)
    x = next(c for c in cases if c.id == "tier2/x")

    miss = _malicious_result(x.staged_file, "BAL_PRIV_MINT", "B")
    gaps = tool_gaps([x], miss)
    assert len(gaps) == 1
    assert gaps[0]["reason"] == "no_expected_family"

    hit = _malicious_result(x.staged_file, "BAL_PRIV_MINT", "A")
    assert tool_gaps([x], hit) == []


def test_format_gaps_md(tmp_cases: Path) -> None:
    assert format_gaps_md([]) == "(no gaps)\n"

    cases = load_cases(tmp_cases)
    mal = next(c for c in cases if c.id == "tier1/EXIT_ADDR_GATE/mal")
    gaps = tool_gaps(cases, _malicious_result(mal.staged_file, "PRIV_ROLE", "A", severity="INFO"))
    md = format_gaps_md(gaps)
    assert mal.id in md
    assert "no_expected_rule" in md
