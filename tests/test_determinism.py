from __future__ import annotations

import json
from copy import deepcopy

from baybench.determinism import canonical, determinism_report, is_deterministic
from baybench.models import parse_result


def _run(*, file_a: str = "a.sol", lines: list[int] | None = None) -> dict:
    if lines is None:
        lines = [4, 5]
    return {
        "tool": {"name": "kw", "version": "0.1"},
        "results": [
            {
                "file": "b.sol",
                "verdict": "Benign",
                "findings": [
                    {
                        "rule_id": "Z_RULE",
                        "family": "A",
                        "severity": "INFO",
                        "function": "foo",
                        "lines": [1],
                        "reasoning": "looks ok",
                    },
                    {
                        "rule_id": "A_RULE",
                        "family": "B",
                        "severity": "HIGH",
                        "function": "bar",
                        "lines": [10],
                        "reasoning": "suspicious",
                    },
                ],
            },
            {
                "file": file_a,
                "verdict": "Malicious",
                "findings": [
                    {
                        "rule_id": "EXIT_ADDR_GATE",
                        "family": "A",
                        "severity": "HIGH",
                        "contract": "M",
                        "function": "setBots",
                        "lines": list(lines),
                        "reasoning": "hardcoded allowlist",
                    }
                ],
            },
        ],
    }


def _reordered_with_input_prefix(src: dict) -> dict:
    a = next(r for r in src["results"] if r["verdict"] == "Malicious")
    b = next(r for r in src["results"] if r["verdict"] == "Benign")
    return {
        "tool": deepcopy(src["tool"]),
        "results": [
            {
                "file": "/input/" + a["file"].removeprefix("/input/"),
                "verdict": a["verdict"],
                "findings": deepcopy(a["findings"]),
            },
            {
                "file": "/input/" + b["file"].removeprefix("/input/"),
                "verdict": b["verdict"],
                "findings": list(reversed(deepcopy(b["findings"]))),
            },
        ],
    }


def test_is_deterministic_true_despite_order_and_input_prefix() -> None:
    run1 = _run()
    run2 = _reordered_with_input_prefix(run1)
    ok, diff = is_deterministic(run1, run2)
    assert (ok, diff) == (True, "")


def test_is_deterministic_true_when_lines_order_differs() -> None:
    run1 = _run(lines=[47, 41])
    run2 = _reordered_with_input_prefix(run1)
    run2["results"][0]["findings"][0]["lines"] = [41, 47]
    ok, diff = is_deterministic(run1, run2)
    assert (ok, diff) == (True, "")


def test_is_deterministic_false_on_verdict_change() -> None:
    run1 = _run()
    run2 = deepcopy(run1)
    run2["results"][1]["verdict"] = "Benign"
    ok, diff = is_deterministic(run1, run2)
    assert ok is False
    assert "run1" in diff and "run2" in diff
    assert any(line.startswith("-") and "Malicious" in line for line in diff.splitlines())
    assert any(line.startswith("+") and "Benign" in line for line in diff.splitlines())


def test_is_deterministic_false_on_reasoning_change() -> None:
    run1 = _run()
    run2 = deepcopy(run1)
    run2["results"][1]["findings"][0]["reasoning"] = "different explanation"
    ok, diff = is_deterministic(run1, run2)
    assert ok is False
    assert diff


def test_canonical_does_not_mutate_input() -> None:
    src = _run(file_a="/input/a.sol")
    before = json.dumps(src, sort_keys=True)
    canonical(src)
    after = json.dumps(src, sort_keys=True)
    assert before == after


def test_canonical_accepts_tool_result() -> None:
    src = _run()
    parsed = parse_result(src)
    assert canonical(parsed) == canonical(src)


def test_determinism_report_single_and_mismatch() -> None:
    run = _run()
    single = determinism_report([run])
    assert single == {"n_runs": 1, "deterministic": None, "diffs": []}

    changed = deepcopy(run)
    changed["results"][1]["verdict"] = "Uncertain"
    report = determinism_report([run, run, changed])
    assert report["n_runs"] == 3
    assert report["deterministic"] is False
    assert len(report["diffs"]) == 1
    assert report["diffs"][0]["run"] == 2
    assert report["diffs"][0]["diff"]


def test_canonical_missing_optional_fields_match_empty() -> None:
    no_findings = {
        "tool": {"name": "kw"},
        "results": [{"file": "a.sol", "verdict": "Benign"}],
    }
    empty_findings = {
        "tool": {"name": "kw"},
        "results": [{"file": "a.sol", "verdict": "Benign", "findings": []}],
    }
    assert canonical(no_findings) == canonical(empty_findings)

    no_lines = {
        "tool": {"name": "kw"},
        "results": [
            {
                "file": "a.sol",
                "verdict": "Malicious",
                "findings": [
                    {"rule_id": "EXIT_ADDR_GATE", "family": "A", "severity": "HIGH"}
                ],
            }
        ],
    }
    empty_lines = {
        "tool": {"name": "kw"},
        "results": [
            {
                "file": "a.sol",
                "verdict": "Malicious",
                "findings": [
                    {
                        "rule_id": "EXIT_ADDR_GATE",
                        "family": "A",
                        "severity": "HIGH",
                        "lines": [],
                    }
                ],
            }
        ],
    }
    assert canonical(no_lines) == canonical(empty_lines)
