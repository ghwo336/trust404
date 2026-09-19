from __future__ import annotations

from math import ceil
from statistics import median
from typing import Sequence

from .models import Case, FileResult, ToolResult

TIER_WEIGHTS = {
    "tier0_judge": 1.0,
    "tier1_pairs": 2.0,
    "tier2_realworld": 1.0,
    "tier3_benign_risky": 2.0,
}


def verdict_score(actual: str | None, preferred: str, accepted: Sequence[str]) -> float:
    if actual is None:
        return 0.0
    if actual == preferred:
        return 1.0
    if actual in accepted:
        return 0.75
    if actual == "Uncertain":
        return 0.5
    return 0.0


def percentile(values: Sequence[float], p: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    n = len(xs)
    rank = max(1, min(n, ceil(p / 100.0 * n)))
    return xs[rank - 1]


def _round4(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 4)


def _mean(values: Sequence[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def case_row(case: Case, fr: FileResult | None) -> dict:
    findings = fr.findings if fr is not None else ()
    actual = fr.verdict if fr is not None else None
    reason = fr.reason if fr is not None else ""
    fired_rule_ids = sorted({f.rule_id for f in findings})
    fired_families = sorted({f.family for f in findings})
    family_hit: bool | None = None
    if case.is_malicious and case.expected_families:
        family_hit = any(f.family in case.expected_families for f in findings)
    rule_hit: bool | None = None
    if case.is_malicious and case.expected_rule_ids:
        rule_hit = any(f.rule_id in case.expected_rule_ids for f in findings)
    evidence_hit: bool | None = None
    if case.expected_functions:
        evidence_hit = any(f.function in case.expected_functions for f in findings)
    high_fp: bool | None = None
    if case.is_benign:
        high_fp = any(f.severity == "HIGH" for f in findings)
    return {
        "id": case.id,
        "tier": case.tier,
        "preferred": case.preferred_verdict,
        "accepted": list(case.accepted_verdicts),
        "actual": actual,
        "score": verdict_score(actual, case.preferred_verdict, case.accepted_verdicts),
        "missing": fr is None,
        "reason": reason,
        "uncertain": actual == "Uncertain",
        "compile_fail": "compile_failed" in reason,
        "family_hit": family_hit,
        "rule_hit": rule_hit,
        "evidence_hit": evidence_hit,
        "high_fp": high_fp,
        "fired_rule_ids": fired_rule_ids,
        "fired_families": fired_families,
        "exact": actual is not None and actual == case.preferred_verdict,
    }


def aggregate(rows: list[dict], timings: Sequence[float] | None = None) -> dict:
    n = len(rows)
    scores = [row["score"] for row in rows]
    family_hits = [row["family_hit"] for row in rows if row["family_hit"] is not None]
    rule_hits = [row["rule_hit"] for row in rows if row["rule_hit"] is not None]
    high_fps = [row["high_fp"] for row in rows if row["high_fp"] is not None]
    evidence_hits = [row["evidence_hit"] for row in rows if row["evidence_hit"] is not None]
    return {
        "n_cases": n,
        "mean_verdict_score": _round4(_mean(scores) if scores else 0.0),
        "family_recall": _round4(_mean(family_hits)),
        "rule_recall": _round4(_mean(rule_hits)),
        "high_fp_rate": _round4(_mean(high_fps)),
        "evidence_hit_rate": _round4(_mean(evidence_hits)),
        "uncertain_rate": _round4(sum(1 for row in rows if row["uncertain"]) / n if n else 0.0),
        "missing_count": sum(1 for row in rows if row["missing"]),
        "compile_fail_count": sum(1 for row in rows if row["compile_fail"]),
        "runtime_p50": _round4(percentile(timings, 50) if timings is not None else None),
        "runtime_p95": _round4(percentile(timings, 95) if timings is not None else None),
    }


def score_run(
    cases: Sequence[Case],
    tool_result: ToolResult,
    catalog: dict,
    timings: Sequence[float] | None = None,
) -> dict:
    by_file = tool_result.by_file()
    rows = [case_row(case, by_file.get(case.staged_file)) for case in cases]
    rows_by_tier: dict[str, list[dict]] = {}
    for row in rows:
        rows_by_tier.setdefault(row["tier"], []).append(row)
    per_tier = {tier: aggregate(tier_rows) for tier, tier_rows in rows_by_tier.items()}
    per_family = {
        fam: aggregate(
            [
                row
                for case, row in zip(cases, rows)
                if case.is_malicious and fam in case.expected_families
            ]
        )
        for fam in catalog["families"]
    }
    staged = {case.staged_file for case in cases}
    extra_results = sorted(key for key in by_file if key not in staged)
    tier0_rows = [row for row in rows if row["tier"] == "tier0_judge"]
    tier0_exact = {
        "k": sum(1 for row in tier0_rows if row["exact"]),
        "n": len(tier0_rows),
    }
    if per_tier:
        weight_sum = sum(TIER_WEIGHTS.get(tier, 1.0) for tier in per_tier)
        weighted_score = (
            sum(
                TIER_WEIGHTS.get(tier, 1.0) * per_tier[tier]["mean_verdict_score"]
                for tier in per_tier
            )
            / weight_sum
        )
    else:
        weighted_score = 0.0
    return {
        "tool": tool_result.tool_name,
        "tool_version": tool_result.tool_version,
        "n_cases": len(cases),
        "overall": aggregate(rows, timings),
        "weighted_score": round(weighted_score, 4),
        "tier0_exact": tier0_exact,
        "per_tier": per_tier,
        "per_family": per_family,
        "extra_results": extra_results,
        "cases": rows,
    }
