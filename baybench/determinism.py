from __future__ import annotations

import copy
import difflib
import json

from .models import ToolResult, result_to_dict, normalize_result_file


def _finding_sort_key(finding: dict) -> tuple:
    lines = finding.get("lines") or []
    return (
        finding.get("rule_id") or "",
        finding.get("contract") or "",
        finding.get("function") or "",
        tuple(sorted(lines)),
        finding.get("severity") or "",
    )


def canonical(obj: dict | ToolResult) -> dict:
    if isinstance(obj, ToolResult):
        obj = result_to_dict(obj)
    data = copy.deepcopy(obj)
    results = data.get("results")
    if results is None:
        results = []
        data["results"] = results
    for result in results:
        result["file"] = normalize_result_file(result.get("file") or "")
        findings = result.get("findings")
        if findings is None:
            findings = []
            result["findings"] = findings
        for finding in findings:
            lines = finding.get("lines")
            if lines is None:
                finding["lines"] = []
            else:
                finding["lines"] = sorted(lines)
        findings.sort(key=_finding_sort_key)
    results.sort(key=lambda r: r.get("file") or "")
    return data


def canonical_json(obj: dict | ToolResult) -> str:
    return json.dumps(canonical(obj), sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def is_deterministic(a: dict | ToolResult, b: dict | ToolResult) -> tuple[bool, str]:
    ja = canonical_json(a)
    jb = canonical_json(b)
    if ja == jb:
        return True, ""
    diff = "".join(
        difflib.unified_diff(
            ja.splitlines(True),
            jb.splitlines(True),
            fromfile="run1",
            tofile="run2",
        )
    )
    return False, diff


def determinism_report(runs: list[dict | ToolResult]) -> dict:
    n_runs = len(runs)
    if n_runs < 2:
        return {"n_runs": n_runs, "deterministic": None, "diffs": []}
    diffs = []
    baseline = runs[0]
    for i, run in enumerate(runs[1:], start=1):
        ok, diff = is_deterministic(baseline, run)
        if not ok:
            diffs.append({"run": i, "diff": diff})
    return {"n_runs": n_runs, "deterministic": not diffs, "diffs": diffs}
