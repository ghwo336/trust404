"""Severity adjustment (discriminators) and file verdict / reason.

Decisive mode (Phase 5; spec §`policy.py` — decisive mode). After finalize,
severity is HIGH (counting), MED (STRUCT_EXTERNAL_GATE only), or INFO (evidence).

Concealment rules (HIGH-base) need no override: OWN_HIDDEN_ROLE, OWN_FAKE_RENOUNCE,
VIEW_CALLER_DEPENDENT, BAL_TRANSFER_HIDDEN_MINT, LEAK_EXEMPT_PATH, EXIT_CALLBACK_CYCLE.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Literal

from detector.model import Finding

BOUNDING = frozenset(
    {
        "constant_cap",
        "fee_cap",
        "constant_floor",
        "bounded_window",
        "ungate_exists",
        "no_custody",
        "foreign_only",
        "two_step_handoff",
        "one_shot_initializer",
        "representation_switch",
    }
)

GOVERNANCE = frozenset(
    {
        "managed_role",
        "issuer_token",
        "role_separated_cap",
    }
)

DECISIVE_MED = frozenset(
    {
        "HONEYPOT_LEGACY",
        "PONZI_SHAPE",
        "STRUCT_PROXY_EOA_ADMIN",
        "OWN_TX_ORIGIN",
    }
)

_DROP = frozenset(
    {
        "two_step_handoff",
        "one_shot_initializer",
        "representation_switch",
    }
)

_CANCEL_IF_PRIV_BYPASS = frozenset(
    {
        "ungate_exists",
        "constant_floor",
        "bounded_window",
    }
)

_DiscClass = Literal["bounding", "governance", "other"]


def _disc_class(name: str) -> _DiscClass:
    if name in BOUNDING:
        return "bounding"
    if name in GOVERNANCE:
        return "governance"
    return "other"


def _bounding_applied(discs: tuple[str, ...]) -> bool:
    names = set(discs)
    cancel = "priv_bypass" in names
    for name in names:
        match _disc_class(name):
            case "bounding":
                if name in _DROP:
                    continue
                if cancel and name in _CANCEL_IF_PRIV_BYPASS:
                    continue
                return True
            case "governance":
                continue
            case "other":
                continue
            case _ as unreachable:
                raise AssertionError(f"unreachable discriminator class: {unreachable}")
    return False


def _is_counting(finding: Finding, bounding: bool) -> bool:
    if bounding:
        return False
    if finding.rule_id == "FEE_ADDR_MUTABLE":
        return False
    if finding.rule_id == "STRUCT_EXTERNAL_GATE":
        return False
    if finding.rule_id == "PRIV_ROLE":
        return False
    if finding.base_severity == "HIGH":
        return True
    if finding.rule_id in DECISIVE_MED:
        return True
    if finding.rule_id == "EXIT_TIME_GATE" and "no_expiry" in finding.discriminators:
        return True
    if finding.rule_id == "SLITHER_HIGH_OVERLAY" and "evidence_only" not in finding.discriminators:
        return True
    return False


def _target_severity(finding: Finding, bounding: bool) -> Literal["HIGH", "MED", "INFO"]:
    if finding.rule_id == "STRUCT_EXTERNAL_GATE":
        return "MED"
    if finding.rule_id == "FEE_ADDR_MUTABLE":
        return "INFO"
    if _is_counting(finding, bounding):
        return "HIGH"
    return "INFO"


def adjust(finding: Finding) -> Finding | None:
    """Apply bounding / governance / drop; set severity to HIGH, MED, or INFO."""
    if _DROP.intersection(finding.discriminators):
        return None
    bounding = _bounding_applied(finding.discriminators)
    severity = _target_severity(finding, bounding)
    match severity:
        case "HIGH" | "MED" | "INFO":
            if finding.severity == severity:
                return finding
            return replace(finding, severity=severity)
        case _ as unreachable:
            raise AssertionError(f"unreachable severity: {unreachable}")


def decide(findings: list[Finding]) -> tuple[str, str]:
    """File verdict from finalized findings. spec §policy.py decide."""
    if any(finding.severity == "HIGH" for finding in findings):
        return "Malicious", ""
    if any(finding.rule_id == "STRUCT_EXTERNAL_GATE" for finding in findings):
        return "Uncertain", "external_dependency"
    return "Benign", ""


def finalize(findings: list[Finding]) -> list[Finding]:
    """Drop DROP-class findings and assign HIGH / MED / INFO."""
    adjusted: list[Finding] = []
    for finding in findings:
        out = adjust(finding)
        if out is not None:
            adjusted.append(out)
    return adjusted
