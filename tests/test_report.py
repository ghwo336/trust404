from __future__ import annotations

import json
from pathlib import Path

from baybench.catalog import load_catalog
from baybench.models import load_cases, parse_result
from baybench.report import build_report, render_markdown, write_report

MAL_FILE = "tier1/EXIT_ADDR_GATE/mal/mal.sol"
BEN_FILE = "tier1/EXIT_ADDR_GATE/ben/ben.sol"
USDC_FILE = "tier3/usdc/usdc.sol"


def _run_result() -> dict:
    tool_result = parse_result(
        {
            "tool": {"name": "kw", "version": "0.1"},
            "results": [
                {
                    "file": MAL_FILE,
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
                            "severity": "INFO",
                        }
                    ],
                },
                {
                    "file": USDC_FILE,
                    "verdict": "Uncertain",
                    "reason": "external_dependency",
                },
            ],
        }
    )
    return {
        "result": tool_result,
        "wall_s": 1.25,
        "timings": [1.25],
    }


def test_build_report_has_core_keys(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    catalog = load_catalog()
    run_result = _run_result()
    rep = build_report("kw", cases, run_result, catalog)

    assert set(rep) >= {"scoring", "coverage", "gaps", "determinism"}
    assert rep["tool"] == "kw"
    assert rep["n_cases"] == len(cases)
    assert "overall" in rep["scoring"]
    assert "rules_missing_pair" in rep["coverage"]
    assert "runtime" in rep
    assert "p50" in rep["runtime"]
    assert "p95" in rep["runtime"]


def test_render_markdown_has_title_gate_and_tier_table(tmp_cases: Path) -> None:
    cases = load_cases(tmp_cases)
    rep = build_report("kw", cases, _run_result(), load_catalog())
    md = render_markdown(rep)

    assert isinstance(md, str)
    assert "# BAYBENCH report" in md
    assert "rules_missing_pair" in md
    assert "| tier |" in md
    assert "mean_score" in md
    assert "family_recall" in md


def test_write_report_creates_md_and_json(tmp_cases: Path, tmp_path: Path) -> None:
    cases = load_cases(tmp_cases)
    rep = build_report("kw", cases, _run_result(), load_catalog())
    reports_dir = tmp_path / "reports"
    md_path, json_path = write_report(reports_dir, rep)

    assert md_path == reports_dir / "kw" / "report.md"
    assert json_path == reports_dir / "kw" / "report.json"
    assert md_path.is_file()
    assert json_path.is_file()
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["tool"] == "kw"
    assert "# BAYBENCH report" in md_path.read_text(encoding="utf-8")
