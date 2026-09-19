"""Judge-facing submission adapter: top-level walk, deadline loop, schema objects."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from jsonschema.validators import Draft202012Validator

from detector.compile import is_temp_copy
from detector.describe import REASON_SENTENCES, discriminator_title, rule_explanation, rule_title
from detector.engine import analyze_file, is_dependency_target
from detector.model import FileResult, Finding

logger = logging.getLogger("detector.submission")

DEFAULT_BUDGET_S = 480.0
_SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "judge.schema.json"

_BOUNDED_DISCRIMINATORS = frozenset(
    {
        "constant_cap",
        "fee_cap",
        "constant_floor",
        "bounded_window",
        "ungate_exists",
        "no_custody",
        "foreign_only",
    }
)
_GOVERNANCE_DISCRIMINATORS = frozenset(
    {
        "managed_role",
        "issuer_token",
        "role_separated_cap",
    }
)
_BACKDOOR_RULES = frozenset(
    {
        "OWN_HIDDEN_ROLE",
        "OWN_FAKE_RENOUNCE",
        "VIEW_CALLER_DEPENDENT",
        "BAL_TRANSFER_HIDDEN_MINT",
        "LEAK_EXEMPT_PATH",
        "EXIT_CALLBACK_CYCLE",
        "STRUCT_DELEGATECALL_SETTABLE",
        "STRUCT_SELFDESTRUCT",
    }
)

BENIGN_NO_FINDINGS = (
    "no privileged writer of balances, exit gates, fees or value sinks; "
    "no delegatecall/selfdestruct escape hatch"
)
BENIGN_BOUNDED = (
    "privileged controls present but every one is bounded in code or off the transfer path; "
    "no unbounded privileged path to user assets"
)
BUDGET_REASON = "global time budget exhausted before this file was analysed"


def list_top_level_sol(input_dir: Path, *, recursive: bool = False) -> list[Path]:
    root = Path(input_dir)
    if not recursive:
        files: list[Path] = []
        try:
            children = sorted(root.iterdir(), key=lambda item: item.name)
        except OSError:
            raise
        for child in children:
            if child.is_file() and child.suffix == ".sol" and not is_temp_copy(child):
                files.append(child)
        return files
    found: list[Path] = []
    seen: set[str] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            resolved = str(current.resolve())
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        for child in children:
            if child.is_dir():
                stack.append(child)
            elif child.is_file() and child.suffix == ".sol" and not is_temp_copy(child):
                found.append(child)
    found = [path for path in found if not is_dependency_target(path, root)]
    found.sort(key=lambda path: path.name)
    return found


def validate_against_schema(objs: list[dict]) -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(objs)


def run_submission(
    input_dir: Path,
    *,
    timeout_s: int,
    budget_s: float = DEFAULT_BUDGET_S,
    recursive: bool = False,
    strict: bool = False,
    now=time.monotonic,
) -> list[dict]:
    try:
        paths = list_top_level_sol(input_dir, recursive=recursive)
    except OSError as exc:
        logger.warning("cannot list %s: %s", input_dir, exc)
        return []
    if not paths:
        logger.warning("no .sol files under %s", input_dir)
        return []
    logger.info(
        "submission: %s file(s) under %s (budget=%ss timeout=%ss recursive=%s)",
        len(paths),
        input_dir,
        budget_s,
        timeout_s,
        recursive,
    )
    start = now()
    objs: list[dict] = []
    for path in paths:
        elapsed = now() - start
        if elapsed >= budget_s:
            logger.info("budget_exhausted: skipping %s", path.name)
            objs.append(_budget_object(path.name))
            continue
        remaining = budget_s - elapsed
        per_timeout = min(timeout_s, remaining)
        if not isinstance(per_timeout, int):
            per_timeout = max(1, int(per_timeout))
        if per_timeout < 1:
            per_timeout = 1
        try:
            result = analyze_file(
                path,
                rel=path.name,
                timeout_s=per_timeout,
                input_root=input_dir,
            )
        except Exception as exc:
            logger.warning("analyze_file failed for %s: %s", path.name, exc)
            result = FileResult(path.name, "Uncertain", reason="analysis_error")
        objs.append(to_judge_object(result, path))
    should_validate = strict or os.environ.get("DETECTOR_VALIDATE") == "1"
    if should_validate:
        try:
            validate_against_schema(objs)
        except Exception as exc:
            logger.warning("judge schema validation failed: %s", exc)
    return objs


def to_judge_object(result: FileResult, source_path: Path) -> dict:
    ordered = _ordered_findings(result.findings)
    high = [finding for finding in ordered if finding.severity == "HIGH"]
    match result.verdict:
        case "Malicious":
            verdict = "MALICIOUS"
        case "Benign":
            verdict = "BENIGN"
        case "Uncertain":
            verdict = "UNCERTAIN"
        case _ as unreachable:
            raise AssertionError(f"unreachable verdict: {unreachable}")
    obj: dict = {
        "file": source_path.name,
        "verdict": verdict,
        "reasons": _reasons_for(result, ordered),
        "evidence": _evidence_for(ordered, source_path, verdict=verdict),
    }
    _apply_risk_fields(obj, result, high, ordered)
    return obj


def _budget_object(filename: str) -> dict:
    return {
        "file": filename,
        "verdict": "UNCERTAIN",
        "reasons": [BUDGET_REASON],
        "evidence": [],
        "risk_level": "MEDIUM",
        "risk_type": "NONE",
        "confidence": 0.0,
    }


def _ordered_findings(findings: tuple[Finding, ...]) -> list[Finding]:
    high: list[Finding] = []
    med: list[Finding] = []
    info: list[Finding] = []
    for finding in findings:
        match finding.severity:
            case "HIGH":
                high.append(finding)
            case "MED":
                med.append(finding)
            case "INFO":
                info.append(finding)
            case _ as unreachable:
                raise AssertionError(f"unreachable severity: {unreachable}")
    return high + med + info


def _reason_sentence(reason: str) -> str:
    sentence = REASON_SENTENCES.get(reason, reason.replace("_", " "))
    if not str(sentence).strip():
        return "manual review required"
    return sentence


def _discriminator_notes(names: tuple[str, ...]) -> str:
    parts: list[str] = []
    for name in names:
        title = discriminator_title(name)
        if name in _BOUNDED_DISCRIMINATORS:
            parts.append(f"(bounded: {title})")
        elif name in _GOVERNANCE_DISCRIMINATORS:
            parts.append(f"(governance: {title})")
        else:
            parts.append(f"({title})")
    if not parts:
        return ""
    return " " + " ".join(parts)


def _finding_reason_text(finding: Finding) -> str:
    text = f"{rule_title(finding.rule_id)} — {finding.reasoning}"
    explanation = rule_explanation(finding.rule_id)
    if explanation:
        text = f"{text}; {explanation}"
    return text + _discriminator_notes(finding.discriminators)


def _per_rule_reasons(ordered: list[Finding]) -> list[str]:
    reasons: list[str] = []
    seen: set[str] = set()
    for finding in ordered:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        reasons.append(_finding_reason_text(finding))
    return reasons


def _reasons_for(result: FileResult, ordered: list[Finding]) -> list[str]:
    per_rule = _per_rule_reasons(ordered)
    match result.verdict:
        case "Malicious":
            if per_rule:
                return per_rule
            return ["malicious control path detected"]
        case "Benign":
            if not ordered:
                return [BENIGN_NO_FINDINGS]
            reasons: list[str] = []
            if all(finding.severity == "INFO" for finding in ordered):
                reasons.append(BENIGN_BOUNDED)
            reasons.extend(per_rule)
            return reasons
        case "Uncertain":
            reasons = [_reason_sentence(result.reason), *per_rule]
            reasons = [row for row in reasons if row]
            if not reasons:
                reasons = ["manual review required"]
            return reasons
        case _ as unreachable:
            raise AssertionError(f"unreachable verdict: {unreachable}")


def _source_line_count(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    return len(text.splitlines())


def _evidence_for(ordered: list[Finding], source_path: Path, *, verdict: str) -> list[dict]:
    n_lines = _source_line_count(source_path)
    items: list[dict] = []
    seen: set[tuple[str, int | None]] = set()
    for finding in ordered:
        function = finding.function or finding.contract or "<contract>"
        raw_line = finding.lines[0] if finding.lines else None
        line: int | None
        if raw_line is None or n_lines is None:
            line = None
        else:
            upper = n_lines if n_lines >= 1 else 1
            line = max(1, min(int(raw_line), upper))
        key = (function, line)
        if key in seen:
            continue
        seen.add(key)
        item: dict = {"function": function}
        if line is not None:
            item["line"] = line
        items.append(item)
    if verdict == "MALICIOUS" and not items:
        logger.warning("MALICIOUS %s has no evidence; inserting fallback", source_path.name)
        fallback = "<contract>"
        if ordered:
            fallback = ordered[0].function or ordered[0].contract or "<contract>"
        items.append({"function": fallback, "line": 1})
    return items


def _malicious_risk_type(high: list[Finding]) -> str:
    high_ids = {finding.rule_id for finding in high}
    if high_ids == {"SLITHER_HIGH_OVERLAY"}:
        return "VULNERABILITY"
    for finding in high:
        if finding.family in {"D", "E"} or finding.rule_id in _BACKDOOR_RULES:
            return "BACKDOOR"
    return "BACKDOOR"


def _apply_risk_fields(
    obj: dict,
    result: FileResult,
    high: list[Finding],
    ordered: list[Finding],
) -> None:
    match result.verdict:
        case "Malicious":
            n_high_rules = len({finding.rule_id for finding in high})
            obj["risk_level"] = "CRITICAL" if n_high_rules >= 2 else "HIGH"
            obj["risk_type"] = _malicious_risk_type(high)
            obj["confidence"] = 0.9 if n_high_rules >= 2 else 0.8
        case "Uncertain":
            obj["risk_level"] = "MEDIUM"
            obj["confidence"] = 0.3
        case "Benign":
            if ordered:
                obj["risk_level"] = "LOW"
                obj["risk_type"] = "CENTRALIZATION"
                obj["confidence"] = 0.7
            else:
                obj["risk_type"] = "NONE"
                obj["confidence"] = 0.85
        case _ as unreachable:
            raise AssertionError(f"unreachable verdict: {unreachable}")
