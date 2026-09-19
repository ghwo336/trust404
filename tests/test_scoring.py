from __future__ import annotations

from pathlib import Path

import pytest

from baybench.catalog import load_catalog
from baybench.models import load_cases, parse_result
from baybench.scoring import percentile, score_run, verdict_score

MAL_FILE = "tier1/EXIT_ADDR_GATE/mal/mal.sol"
BEN_FILE = "tier1/EXIT_ADDR_GATE/ben/ben.sol"
USDC_FILE = "tier3/usdc/usdc.sol"


def _tool_result(
    *,
    include_usdc: bool = True,
    ben_severity: str = "INFO",
    extra: bool = True,
    mal_file: str = MAL_FILE,
    usdc_reason: str = "external_dependency",
    usdc_verdict: str = "Uncertain",
):
    results: list[dict] = [
        {
            "file": mal_file,
            "verdict": "Malicious",
            "findings": [
                {
                    "rule_id": "EXIT_ADDR_GATE",
                    "family": "A",
                    "severity": "HIGH",
                    "function": "setBots",
                }
            ],
        },
        {
            "file": BEN_FILE,
            "verdict": "Benign",
            "findings": [
                {
                    "rule_id": "PRIV_ROLE",
                    "family": "A",
                    "severity": ben_severity,
                }
            ],
        },
    ]
    if include_usdc:
        results.append(
            {
                "file": USDC_FILE,
                "verdict": usdc_verdict,
                "reason": usdc_reason,
            }
        )
    if extra:
        results.append({"file": "tier9/nothing.sol", "verdict": "Benign"})
    return parse_result({"tool": {"name": "kw", "version": "0.1"}, "results": results})


@pytest.mark.parametrize(
    "actual, preferred, accepted, expected",
    [
        ("Malicious", "Malicious", ["Malicious"], 1.0),
        ("Uncertain", "Benign", ["Benign", "Uncertain"], 0.75),
        ("Uncertain", "Malicious", ["Malicious"], 0.5),
        ("Benign", "Malicious", ["Malicious"], 0.0),
        (None, "Malicious", ["Malicious"], 0.0),
        ("Benign", "Benign", ["Benign", "Uncertain"], 1.0),
    ],
)
def test_verdict_score_table(
    actual: str | None, preferred: str, accepted: list[str], expected: float
) -> None:
    assert verdict_score(actual, preferred, accepted) == expected


def test_percentile() -> None:
    assert percentile([], 50) is None
    assert percentile([1, 2, 3, 4], 50) == 2
    assert percentile([1, 2, 3, 4], 95) == 4
    assert percentile([7], 95) == 7


def test_score_run_happy_path(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    catalog = load_catalog()
    out = score_run(cases, _tool_result(), catalog)

    overall = out["overall"]
    assert overall["n_cases"] == 3
    assert overall["mean_verdict_score"] == round((1 + 1 + 0.75) / 3, 4)
    assert overall["family_recall"] == 1.0
    assert overall["rule_recall"] == 1.0
    assert overall["evidence_hit_rate"] == 1.0
    assert overall["high_fp_rate"] == 0.0
    assert overall["uncertain_rate"] == round(1 / 3, 4)
    assert overall["missing_count"] == 0
    assert set(out["per_tier"]) == {"tier1_pairs", "tier3_benign_risky"}
    assert out["per_tier"]["tier1_pairs"]["mean_verdict_score"] == 1.0
    assert out["per_family"]["A"]["n_cases"] == 1
    assert out["per_family"]["G"]["n_cases"] == 0
    assert out["extra_results"] == ["tier9/nothing.sol"]
    assert out["weighted_score"] == round((2.0 * 1.0 + 2.0 * 0.75) / 4.0, 4)


def test_missing_result(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    out = score_run(cases, _tool_result(include_usdc=False), load_catalog())
    usdc = next(row for row in out["cases"] if row["id"] == "tier3/usdc")
    assert usdc["missing"] is True
    assert usdc["actual"] is None
    assert usdc["score"] == 0.0
    assert out["overall"]["missing_count"] == 1
    assert out["overall"]["uncertain_rate"] == 0.0


def test_high_fp_rate(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    out = score_run(cases, _tool_result(ben_severity="HIGH"), load_catalog())
    assert out["overall"]["high_fp_rate"] == 0.5


def test_compile_fail(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    out = score_run(
        cases,
        _tool_result(usdc_reason="compile_failed: ParserError"),
        load_catalog(),
    )
    assert out["overall"]["compile_fail_count"] == 1


def test_input_prefix_still_matches(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    out = score_run(
        cases,
        _tool_result(mal_file="/input/tier1/EXIT_ADDR_GATE/mal/mal.sol"),
        load_catalog(),
    )
    mal = next(row for row in out["cases"] if row["id"] == "tier1/EXIT_ADDR_GATE/mal")
    assert mal["missing"] is False
    assert mal["actual"] == "Malicious"
    assert mal["score"] == 1.0
    assert out["overall"]["missing_count"] == 0


def test_timings_only_on_overall(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    out = score_run(
        cases,
        _tool_result(),
        load_catalog(),
        timings=[1.0, 3.0, 2.0],
    )
    assert out["overall"]["runtime_p50"] == 2.0
    assert out["overall"]["runtime_p95"] == 3.0
    for tier_agg in out["per_tier"].values():
        assert tier_agg["runtime_p50"] is None
