"""Deterministic summary.md renderer."""

from __future__ import annotations

from detector import TOOL_NAME, TOOL_VERSION
from detector.model import FileResult, Finding, canonical_findings


def _loc(finding: Finding) -> str:
    if finding.contract and finding.function:
        return f"{finding.contract}.{finding.function}"
    if finding.contract:
        return finding.contract
    if finding.function:
        return finding.function
    return ""


def _count_verdicts(results: list[FileResult]) -> tuple[int, int, int]:
    malicious = 0
    uncertain = 0
    benign = 0
    for result in results:
        match result.verdict:
            case "Malicious":
                malicious += 1
            case "Uncertain":
                uncertain += 1
            case "Benign":
                benign += 1
            case _ as unreachable:
                raise AssertionError(f"unreachable verdict: {unreachable}")
    return malicious, uncertain, benign


def render_summary(results: list[FileResult], meta: dict) -> str:
    name = meta.get("name") or TOOL_NAME
    version = meta.get("version") or TOOL_VERSION
    ordered = sorted(results, key=lambda item: item.file)
    malicious, uncertain, benign = _count_verdicts(ordered)
    lines = [
        f"# {name} {version}",
        f"files: {len(ordered)}",
        f"Malicious: {malicious}",
        f"Uncertain: {uncertain}",
        f"Benign: {benign}",
        "",
    ]
    for result in ordered:
        lines.append(f"## {result.file}")
        lines.append(f"verdict: {result.verdict}")
        if result.reason:
            lines.append(f"reason: {result.reason}")
        findings = canonical_findings(result.findings)
        if not findings:
            lines.append("_no findings_")
        else:
            lines.append("| rule_id | severity | contract.function | lines | reasoning |")
            lines.append("| --- | --- | --- | --- | --- |")
            for finding in findings:
                line_s = ", ".join(str(n) for n in finding.lines)
                lines.append(
                    f"| {finding.rule_id} | {finding.severity} | {_loc(finding)} | {line_s} | {finding.reasoning} |"
                )
        lines.append("")
    return "\n".join(lines)
