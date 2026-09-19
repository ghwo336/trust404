"""Deterministic, judge-facing summary.md renderer (DT-11).

The text is a pure function of the results list: no timestamps, no absolute paths, and any
ordering of the input yields byte-identical output. results.json is written by model.py; this
module only changes how the same findings are presented.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from detector import TOOL_NAME, TOOL_VERSION, describe
from detector.model import FileResult, Finding, canonical_findings
from detector.rules.base import CATALOG
from detector.rules.overlay import EXPLOIT_SHAPE_CHECKS

SEVERITY_ORDER: tuple[str, ...] = ("HIGH", "MED", "INFO")
INFO_COLLAPSE_THRESHOLD = 6
EMPTY_CELL = "—"
FOOTER = "Analysis is static (Slither IR), name-agnostic and offline; verdict rules: see README."

_ESCALATED_PREFIX = "escalated:"
_GATED_BY_RE = re.compile(r"\bgated by (\S+)")
_COUNT_WORDS = {2: "two", 3: "three", 4: "four", 5: "five"}


# --- small pure helpers ---------------------------------------------------------------------


def _verdict_rank(verdict: str) -> int:
    match verdict:
        case "Malicious":
            return 0
        case "Uncertain":
            return 1
        case "Benign":
            return 2
        case _ as unreachable:
            raise AssertionError(f"unreachable verdict: {unreachable}")


def _severity_rank(severity: str) -> int:
    match severity:
        case "HIGH":
            return 0
        case "MED":
            return 1
        case "INFO":
            return 2
        case _ as unreachable:
            raise AssertionError(f"unreachable severity: {unreachable}")


def _span(start: int, end: int) -> str:
    return str(start) if start == end else f"{start}-{end}"


def compress_lines(lines: Iterable[int]) -> str:
    """(12, 47, 48, 49) -> '12, 47-49'; duplicates and order are normalised; empty -> '—'."""
    uniq = sorted({int(n) for n in lines})
    if not uniq:
        return EMPTY_CELL
    parts: list[str] = []
    start = prev = uniq[0]
    for n in uniq[1:]:
        if n == prev + 1:
            prev = n
            continue
        parts.append(_span(start, prev))
        start = prev = n
    parts.append(_span(start, prev))
    return ", ".join(parts)


def _cell(text: str) -> str:
    """Make arbitrary text safe inside a markdown table cell."""
    flat = " ".join(str(text).replace("\r", "\n").split("\n")).replace("|", "\\|").strip()
    return flat or EMPTY_CELL


def _where(finding: Finding) -> str:
    if finding.contract and finding.function:
        return f"{finding.contract}.{finding.function}"
    return finding.contract or finding.function or ""


def _base_severity(finding: Finding) -> str:
    """Catalog severity; findings rebuilt from results.json carry no base_severity."""
    if finding.base_severity:
        return finding.base_severity
    entry = CATALOG.get(finding.rule_id)
    return entry[1] if entry else ""


def _evidence(finding: Finding) -> str:
    """Reasoning plus a note when the policy moved the severity away from the catalog base."""
    text = finding.reasoning
    base = _base_severity(finding)
    if base and base != finding.severity:
        verb = "downgraded" if _severity_rank(finding.severity) > _severity_rank(base) else "raised"
        note = f"{verb} {base}→{finding.severity}"
        if finding.discriminators:
            note += ": " + ", ".join(describe.discriminator_title(d) for d in finding.discriminators)
        text = f"{text} · {note}" if text.strip() else note
    return text


def _distinct_titles(findings: Iterable[Finding]) -> str:
    seen: list[str] = []
    for finding in findings:
        title = describe.rule_title(finding.rule_id)
        if title not in seen:
            seen.append(title)
    return ", ".join(seen)


def _overlay_check(finding: Finding) -> str:
    return finding.reasoning.split(":", 1)[0].strip()


def _overlay_checks(findings: Sequence[Finding]) -> list[str]:
    overlay = [
        f for f in findings if f.rule_id == "SLITHER_HIGH_OVERLAY" and f.reasoning.strip()
    ]
    all_checks = {_overlay_check(f) for f in overlay}
    # Findings rebuilt from results.json carry no discriminators, so also filter by the check
    # set that policy treats as exploit-shaped; fall back to everything if nothing matches.
    lifting = {
        _overlay_check(f)
        for f in overlay
        if "evidence_only" not in f.discriminators and _overlay_check(f) in EXPLOIT_SHAPE_CHECKS
    }
    return sorted(lifting or all_checks)


def _count_word(n: int) -> str:
    return _COUNT_WORDS.get(n, str(n))


def explain_verdict(verdict: str, reason: str, findings: Sequence[Finding]) -> str:
    """One human sentence for (verdict, reason, findings); the `why` column of the overview."""
    ordered = canonical_findings(findings)
    if reason.startswith(_ESCALATED_PREFIX):
        ids = [item for item in reason[len(_ESCALATED_PREFIX) :].split(",") if item]
        titles = ", ".join(describe.rule_title(item) for item in ids)
        return (
            f"{_count_word(len(ids))} independent privileged controls from different "
            f"families ({titles})"
        )
    if reason == "med_findings":
        base = describe.REASON_SENTENCES[reason]
        titles = _distinct_titles(f for f in ordered if f.severity == "MED")
        return f"{base} ({titles})" if titles else base
    if reason == "slither_high":
        checks = _overlay_checks(ordered)
        return (
            f"Slither exploit-shape finding ({', '.join(checks)})"
            if checks
            else "Slither exploit-shape finding"
        )
    if reason in describe.REASON_SENTENCES:
        return describe.REASON_SENTENCES[reason]
    if reason:
        return f"reason: {reason}"
    match verdict:
        case "Malicious":
            titles = _distinct_titles(f for f in ordered if f.severity == "HIGH")
            return f"HIGH: {titles}" if titles else "Malicious without a recorded HIGH finding"
        case "Uncertain":
            return describe.UNCERTAIN_NO_REASON
        case "Benign":
            if any(f.severity == "INFO" for f in ordered):
                return describe.BENIGN_INFO_ONLY
            return describe.BENIGN_NO_FINDINGS
        case _ as unreachable:
            raise AssertionError(f"unreachable verdict: {unreachable}")


# --- rendering ------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Entry:
    result: FileResult
    findings: tuple[Finding, ...]
    why: str
    counts: tuple[int, int, int]


def _entry(result: FileResult) -> _Entry:
    findings = canonical_findings(result.findings)
    counts = [0, 0, 0]
    for finding in findings:
        counts[_severity_rank(finding.severity)] += 1
    return _Entry(
        result=result,
        findings=findings,
        why=explain_verdict(result.verdict, result.reason, findings),
        counts=(counts[0], counts[1], counts[2]),
    )


def _legend(entries: Sequence[_Entry]) -> list[str]:
    verdict_counts = [0, 0, 0]
    for entry in entries:
        verdict_counts[_verdict_rank(entry.result.verdict)] += 1
    malicious, uncertain, benign = verdict_counts
    return [
        "- Verdicts: **Malicious** = concealed or unbounded control over user funds found · "
        "**Uncertain** = privileged or risky controls found but disclosed, bounded or externally "
        "dependent (manual review) · **Benign** = no privileged control over user funds found.",
        "- Severities: **HIGH** drives Malicious · **MED** drives Uncertain / escalation · "
        "**INFO** is evidence only.",
        f"- Files: {len(entries)} · Malicious {malicious} · Uncertain {uncertain} · Benign {benign}.",
    ]


def _overview(entries: Sequence[_Entry]) -> list[str]:
    lines = ["## Overview", ""]
    if not entries:
        lines += ["_no .sol files found under the input directory_", ""]
        return lines
    lines += [
        "| file | verdict | why | HIGH | MED | INFO |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for entry in entries:
        high, med, info = entry.counts
        lines.append(
            f"| {_cell(entry.result.file)} | {entry.result.verdict} | {_cell(entry.why)} "
            f"| {high} | {med} | {info} |"
        )
    lines.append("")
    return lines


def _table(findings: Sequence[Finding]) -> list[str]:
    rows = [
        "| rule | title | where | lines | evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        rows.append(
            f"| {_cell(finding.rule_id)} | {_cell(describe.rule_title(finding.rule_id))} "
            f"| {_cell(_where(finding))} | {compress_lines(finding.lines)} "
            f"| {_cell(_evidence(finding))} |"
        )
    return rows


def _collapsed_priv_roles(priv: Sequence[Finding]) -> list[str]:
    auth_vars = sorted(
        {match.group(1) for f in priv if (match := _GATED_BY_RE.search(f.reasoning)) is not None}
    )
    head = f"{len(priv)} privileged functions"
    if auth_vars:
        head += f" gated by {', '.join(_cell(v) for v in auth_vars)}"
    return [
        head,
        "",
        "<details>",
        f"<summary>Show all {len(priv)} role-gated functions</summary>",
        "",
        *_table(priv),
        "",
        "</details>",
        "",
    ]


def _group(severity: str, findings: Sequence[Finding]) -> list[str]:
    lines = [f"**{severity}**", ""]
    if severity == "INFO":
        priv = [f for f in findings if f.rule_id == "PRIV_ROLE"]
        if len(priv) > INFO_COLLAPSE_THRESHOLD:
            others = [f for f in findings if f.rule_id != "PRIV_ROLE"]
            if others:
                lines += _table(others) + [""]
            lines += _collapsed_priv_roles(priv)
            return lines
    lines += _table(findings) + [""]
    return lines


def _section(entry: _Entry) -> list[str]:
    result = entry.result
    verdict_line = f"Verdict: **{result.verdict}**"
    if result.reason:
        verdict_line += f" (`{_cell(result.reason)}`)"
    verdict_line += f" — {entry.why}"
    lines = [f"### {_cell(result.file)}", "", verdict_line, ""]
    if not entry.findings:
        lines += ["_no findings_", ""]
        return lines
    for severity in SEVERITY_ORDER:
        group = [f for f in entry.findings if f.severity == severity]
        if group:
            lines += _group(severity, group)
    return lines


def render_summary(results: list[FileResult], meta: dict) -> str:
    name = meta.get("name") or TOOL_NAME
    version = meta.get("version") or TOOL_VERSION
    ordered = sorted(results, key=lambda item: (_verdict_rank(item.verdict), item.file))
    entries = [_entry(result) for result in ordered]
    lines: list[str] = [f"# {name} {version} — offline static analysis report", ""]
    lines += _legend(entries) + [""]
    lines += _overview(entries)
    if entries:
        lines += ["## Findings", ""]
        for entry in entries:
            lines += _section(entry)
    lines += ["---", "", FOOTER]
    return "\n".join(lines) + "\n"
