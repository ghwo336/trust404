from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from .coverage import coverage_report, format_gaps_md, tool_gaps
from .determinism import determinism_report
from .models import Case
from .scoring import score_run


def build_report(
    tool_name: str,
    cases: Sequence[Case],
    run_result: dict,
    catalog: dict,
    all_run_results: list[dict] | None = None,
) -> dict:
    scoring = score_run(
        cases,
        run_result["result"],
        catalog,
        timings=run_result.get("timings"),
    )
    cov = coverage_report(cases, catalog)
    gaps = tool_gaps(cases, run_result["result"])
    determinism = determinism_report(
        [r["result"] for r in (all_run_results or [run_result])]
    )
    return {
        "tool": tool_name,
        "n_cases": len(cases),
        "scoring": scoring,
        "coverage": cov,
        "gaps": gaps,
        "determinism": determinism,
        "runtime": {
            "p50": scoring["overall"].get("runtime_p50"),
            "p95": scoring["overall"].get("runtime_p95"),
        },
    }


def _cell(value) -> str:
    if value is None:
        return "-"
    return str(value)


def _join(values: Sequence[str]) -> str:
    return ", ".join(values) if values else "-"


def _determinism_label(det: bool | None) -> str:
    if det is True:
        return "pass"
    if det is False:
        return "fail"
    return "-"


def render_markdown(rep: dict) -> str:
    scoring = rep.get("scoring") or {}
    overall = scoring.get("overall") or {}
    coverage = rep.get("coverage") or {}
    determinism = rep.get("determinism") or {}
    runtime = rep.get("runtime") or {}
    extra_results = scoring.get("extra_results") or []
    missing_pair = coverage.get("rules_missing_pair") or []
    bb6 = "PASS" if not missing_pair else _join(missing_pair)

    lines = [
        f"# BAYBENCH report — {_cell(rep.get('tool'))}",
        "",
        "## Summary",
        "",
        "| metric | value |",
        "| --- | --- |",
        f"| weighted_score | {_cell(scoring.get('weighted_score'))} |",
        f"| mean_verdict_score | {_cell(overall.get('mean_verdict_score'))} |",
        f"| n_cases | {_cell(rep.get('n_cases'))} |",
        f"| determinism | {_determinism_label(determinism.get('deterministic'))} |",
        f"| runtime_p50 | {_cell(runtime.get('p50'))} |",
        f"| runtime_p95 | {_cell(runtime.get('p95'))} |",
        f"| compile_fail_count | {_cell(overall.get('compile_fail_count'))} |",
        "",
        "## Per-tier",
        "",
        "| tier | n | mean_score | family_recall | rule_recall | high_fp_rate | evidence_hit_rate | uncertain_rate |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    per_tier = scoring.get("per_tier") or {}
    for tier in sorted(per_tier):
        agg = per_tier[tier]
        lines.append(
            "| "
            + " | ".join(
                [
                    tier,
                    _cell(agg.get("n_cases")),
                    _cell(agg.get("mean_verdict_score")),
                    _cell(agg.get("family_recall")),
                    _cell(agg.get("rule_recall")),
                    _cell(agg.get("high_fp_rate")),
                    _cell(agg.get("evidence_hit_rate")),
                    _cell(agg.get("uncertain_rate")),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Per-family",
            "",
            "| family | n_cases | mean_score |",
            "| --- | --- | --- |",
        ]
    )
    per_family = scoring.get("per_family") or {}
    for family in per_family:
        agg = per_family[family]
        lines.append(
            f"| {family} | {_cell(agg.get('n_cases'))} | {_cell(agg.get('mean_verdict_score'))} |"
        )

    zero_families = coverage.get("families_zero_cases") or []
    zero_rules = coverage.get("rules_zero_cases") or []
    unknown_rules = coverage.get("unknown_rule_ids") or []
    lines.extend(
        [
            "",
            "## Coverage",
            "",
            f"families_zero_cases ({len(zero_families)}): {_join(zero_families)}",
            f"rules_zero_cases ({len(zero_rules)}): {_join(zero_rules)}",
            f"rules_missing_pair (BB-6): {bb6}",
            f"unknown_rule_ids: {_join(unknown_rules)}",
            f"extra_results: {_join(extra_results)}",
            "",
            "## Gaps",
            "",
            format_gaps_md(rep.get("gaps") or []).rstrip("\n"),
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def write_report(reports_dir, rep: dict) -> tuple[Path, Path]:
    reports_dir = Path(reports_dir)
    dest = reports_dir / str(rep["tool"])
    dest.mkdir(parents=True, exist_ok=True)
    json_path = dest / "report.json"
    md_path = dest / "report.md"
    json_path.write_text(
        json.dumps(rep, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(rep), encoding="utf-8")
    return md_path, json_path
