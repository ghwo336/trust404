"""Severity adjustment (discriminators) and file verdict / reason."""

from __future__ import annotations

from dataclasses import replace

from detector.model import Finding

CONCEALMENT_RULES = frozenset(
    {
        "OWN_HIDDEN_ROLE",
        "OWN_FAKE_RENOUNCE",
        "VIEW_CALLER_DEPENDENT",
        "BAL_TRANSFER_HIDDEN_MINT",
        "LEAK_EXEMPT_PATH",
        "EXIT_CALLBACK_CYCLE",
    }
)

BOUND_DISCRIMINATORS = frozenset(
    {
        "ungate_exists",
        "constant_floor",
        "bounded_window",
        "constant_cap",
        "role_separated_cap",
        "fee_cap",
        "foreign_only",
        "no_custody",
    }
)

SHAPE_DISCRIMINATORS = frozenset(
    {
        "managed_role",
        "library_role",
        "issuer_token",
    }
)


def _downgrade_rank(target: str) -> int:
    match target:
        case "DROP":
            return 0
        case "INFO":
            return 1
        case "MED":
            return 2
        case _ as unreachable:
            raise AssertionError(f"unreachable downgrade target: {unreachable}")


def adjust(
    finding: Finding,
    *,
    concealed: bool,
    downgrade_to: dict[str, str],
) -> Finding | None:
    if concealed:
        return finding
    matched = [
        (name, downgrade_to[name]) for name in finding.discriminators if name in downgrade_to
    ]
    if not matched:
        return finding
    _name, target = min(matched, key=lambda item: _downgrade_rank(item[1]))
    match target:
        case "DROP":
            return None
        case "MED" | "INFO":
            new_severity = target
        case _ as unreachable:
            raise AssertionError(f"unreachable downgrade target: {unreachable}")
    applied_bound_or_shape = any(
        name in BOUND_DISCRIMINATORS or name in SHAPE_DISCRIMINATORS for name, _tgt in matched
    )
    counts = False if applied_bound_or_shape else finding.counts_for_escalation
    return replace(finding, severity=new_severity, counts_for_escalation=counts)


def decide(
    findings: list[Finding],
    *,
    suppress_escalation: bool = False,
) -> tuple[str, str]:
    if any(finding.severity == "HIGH" for finding in findings):
        return "Malicious", ""
    if any(finding.rule_id == "STRUCT_EXTERNAL_GATE" for finding in findings):
        return "Uncertain", "external_dependency"
    shape_applied = any(
        any(name in SHAPE_DISCRIMINATORS for name in finding.discriminators)
        for finding in findings
    )
    if not suppress_escalation and not shape_applied:
        med = [
            finding
            for finding in findings
            if finding.severity == "MED" and finding.counts_for_escalation
        ]
        rule_ids = {finding.rule_id for finding in med}
        families = {finding.family for finding in med}
        if len(rule_ids) >= 2 and len(families) >= 2:
            return "Malicious", f"escalated:{','.join(sorted(rule_ids))}"
    if any(finding.severity == "MED" for finding in findings):
        return "Uncertain", "med_findings"
    if any(finding.rule_id == "SLITHER_HIGH_OVERLAY" for finding in findings):
        return "Uncertain", "slither_high"
    return "Benign", ""
