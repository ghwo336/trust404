"""Policy: bounding vs governance discriminators and the decisive verdict (Phase 5).

Unit tests use hand-built Findings. Corpus tests follow test_rules_a.py::test_family_a_file_verdict.
Spec: docs/specs/detector.md §`policy.py` — decisive mode.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from detector.describe import (
    BOUNDING_NOTE,
    GOVERNANCE_NOTE,
    bounding_notes,
    governance_notes,
)
from detector.engine import _analyze_in_process
from detector.model import Finding
from detector.policy import BOUNDING, DECISIVE_MED, GOVERNANCE, adjust, decide, finalize
from detector.rules.base import CATALOG
from tests.detector.conftest import CASES, HARNESS, TIER3, tier1_sol

# Concealment rules stay HIGH-base; they need no override under decisive mode.
_CONCEALMENT_HIGH_BASE = frozenset(
    {
        "OWN_HIDDEN_ROLE",
        "OWN_FAKE_RENOUNCE",
        "VIEW_CALLER_DEPENDENT",
        "BAL_TRANSFER_HIDDEN_MINT",
        "LEAK_EXEMPT_PATH",
        "EXIT_CALLBACK_CYCLE",
    }
)

_DROP = frozenset({"two_step_handoff", "one_shot_initializer", "representation_switch"})

_ALL_DISCS = tuple(
    sorted(
        {
            *BOUNDING,
            *GOVERNANCE,
            "priv_bypass",
            "no_expiry",
            "evidence_only",
            "eq_self",
            "library_role",
        }
    )
)


def _finding(
    rule_id: str,
    *,
    family: str | None = None,
    severity: str | None = None,
    discriminators: tuple[str, ...] = (),
    base_severity: str | None = None,
) -> Finding:
    fam, catalog_sev = CATALOG.get(rule_id, (family or "A", severity or "HIGH"))
    return Finding(
        rule_id=rule_id,
        family=family or fam,
        severity=severity or catalog_sev,
        base_severity=base_severity or catalog_sev,
        discriminators=discriminators,
    )


def _apply(findings: list[Finding]) -> tuple[list[Finding], str, str]:
    """finalize then decide — the engine contract (spec §policy.py decisive mode)."""
    adjusted = finalize(findings)
    verdict, reason = decide(adjusted)
    return adjusted, verdict, reason


# --- decide / finalize table (spec §policy.py decisive mode) ---------------------------------


def test_high_is_malicious() -> None:
    findings = [_finding("EXIT_ADDR_GATE", severity="HIGH")]
    assert decide(findings) == ("Malicious", "")


def test_high_beats_external_gate() -> None:
    """STRUCT_EXTERNAL_GATE + one HIGH → Malicious. spec §policy.py decide step 1."""
    findings = [
        _finding("EXIT_ADDR_GATE", severity="HIGH"),
        _finding("STRUCT_EXTERNAL_GATE"),
    ]
    assert decide(findings) == ("Malicious", "")


def test_external_gate_is_uncertain() -> None:
    """STRUCT_EXTERNAL_GATE alone → Uncertain(external_dependency). spec §policy.py decide step 2."""
    adjusted, verdict, reason = _apply([_finding("STRUCT_EXTERNAL_GATE")])
    assert len(adjusted) == 1
    assert adjusted[0].severity == "MED"
    assert (verdict, reason) == ("Uncertain", "external_dependency")


def test_external_gate_plus_decisive_med_is_malicious() -> None:
    """DECISIVE_MED lifts to HIGH, so it beats the abstain. spec §policy.py decide step 1."""
    adjusted, verdict, reason = _apply(
        [
            _finding("STRUCT_EXTERNAL_GATE"),
            _finding("OWN_TX_ORIGIN"),
            _finding("HONEYPOT_LEGACY"),
        ]
    )
    assert (verdict, reason) == ("Malicious", "")
    assert {f.rule_id: f.severity for f in adjusted}["OWN_TX_ORIGIN"] == "HIGH"
    assert {f.rule_id: f.severity for f in adjusted}["HONEYPOT_LEGACY"] == "HIGH"


def test_two_decisive_meds_are_malicious_without_reason() -> None:
    """Escalation retired; each DECISIVE_MED is a counting finding. spec §policy.py."""
    adjusted, verdict, reason = _apply(
        [
            _finding("OWN_TX_ORIGIN"),
            _finding("HONEYPOT_LEGACY"),
        ]
    )
    assert all(f.severity == "HIGH" for f in adjusted)
    assert (verdict, reason) == ("Malicious", "")


def test_no_escalation_same_family() -> None:
    """Two FEE_ADDR_MUTABLE findings never escalate. spec §policy.py (escalation deleted)."""
    adjusted, verdict, reason = _apply(
        [
            _finding("FEE_ADDR_MUTABLE"),
            _finding("FEE_ADDR_MUTABLE"),
        ]
    )
    assert all(f.severity == "INFO" for f in adjusted)
    assert (verdict, reason) == ("Benign", "")


def test_two_med_base_non_decisive_never_escalate() -> None:
    """FEE_ADDR_MUTABLE + STRUCT_EXTERNAL_GATE: no escalation path. spec §policy.py (j)."""
    adjusted, verdict, reason = _apply(
        [
            _finding("FEE_ADDR_MUTABLE"),
            _finding("STRUCT_EXTERNAL_GATE"),
        ]
    )
    assert (verdict, reason) == ("Uncertain", "external_dependency")
    by_id = {f.rule_id: f.severity for f in adjusted}
    assert by_id["FEE_ADDR_MUTABLE"] == "INFO"
    assert by_id["STRUCT_EXTERNAL_GATE"] == "MED"


def test_bound_high_base_is_info_benign() -> None:
    """HIGH-base + constant_cap → INFO, Benign. spec §policy.py (a)."""
    adjusted, verdict, reason = _apply(
        [_finding("BAL_PRIV_MINT", severity="HIGH", discriminators=("constant_cap",))]
    )
    assert len(adjusted) == 1
    assert adjusted[0].severity == "INFO"
    assert adjusted[0].base_severity == "HIGH"
    assert (verdict, reason) == ("Benign", "")


def test_governance_only_stays_high_malicious() -> None:
    """HIGH-base + managed_role only → HIGH, Malicious. spec §policy.py (b)."""
    adjusted, verdict, reason = _apply(
        [_finding("EXIT_ADDR_GATE", severity="HIGH", discriminators=("managed_role",))]
    )
    assert len(adjusted) == 1
    assert adjusted[0].severity == "HIGH"
    assert (verdict, reason) == ("Malicious", "")


def test_bounding_wins_over_governance() -> None:
    """HIGH-base + constant_cap + managed_role → INFO, Benign. spec §policy.py (c)."""
    adjusted, verdict, reason = _apply(
        [
            _finding(
                "BAL_PRIV_MINT",
                severity="HIGH",
                discriminators=("constant_cap", "managed_role"),
            )
        ]
    )
    assert adjusted[0].severity == "INFO"
    assert (verdict, reason) == ("Benign", "")


def test_priv_bypass_cancels_ungate() -> None:
    """ungate_exists + priv_bypass → HIGH. spec §policy.py (d)."""
    adjusted, verdict, reason = _apply(
        [
            _finding(
                "EXIT_GLOBAL_SWITCH",
                severity="HIGH",
                discriminators=("ungate_exists", "priv_bypass"),
            )
        ]
    )
    assert adjusted[0].severity == "HIGH"
    assert (verdict, reason) == ("Malicious", "")


@pytest.mark.parametrize("rule_id", sorted(DECISIVE_MED))
def test_each_decisive_med_alone_is_high_malicious(rule_id: str) -> None:
    """Each DECISIVE_MED rule alone → HIGH, Malicious. spec §policy.py (e)."""
    adjusted, verdict, reason = _apply([_finding(rule_id)])
    assert len(adjusted) == 1
    assert adjusted[0].severity == "HIGH"
    assert (verdict, reason) == ("Malicious", "")


def test_fee_addr_mutable_alone_is_info_benign() -> None:
    """FEE_ADDR_MUTABLE is always INFO. spec §policy.py (f)."""
    adjusted, verdict, reason = _apply([_finding("FEE_ADDR_MUTABLE")])
    assert adjusted[0].severity == "INFO"
    assert (verdict, reason) == ("Benign", "")


def test_overlay_evidence_only_is_benign() -> None:
    """SLITHER_HIGH_OVERLAY + evidence_only → Benign. spec §policy.py (i)."""
    evidence = _finding("SLITHER_HIGH_OVERLAY", discriminators=("evidence_only",))
    adjusted, verdict, reason = _apply([evidence])
    assert adjusted[0].severity == "INFO"
    assert (verdict, reason) == ("Benign", "")


def test_overlay_exploit_shape_is_malicious() -> None:
    """SLITHER_HIGH_OVERLAY without evidence_only → HIGH, Malicious. spec §policy.py (i)."""
    exploit = _finding("SLITHER_HIGH_OVERLAY")
    adjusted, verdict, reason = _apply([exploit])
    assert adjusted[0].severity == "HIGH"
    assert (verdict, reason) == ("Malicious", "")


def test_info_only_is_benign() -> None:
    findings = [_finding("PRIV_ROLE")]
    adjusted, verdict, reason = _apply(findings)
    assert adjusted[0].severity == "INFO"
    assert (verdict, reason) == ("Benign", "")


def test_empty_is_benign() -> None:
    assert decide([]) == ("Benign", "")
    assert finalize([]) == []


def test_decide_takes_only_findings() -> None:
    """The old suppress flag is retired. spec §policy.py decide."""
    assert list(inspect.signature(decide).parameters) == ["findings"]
    assert decide([_finding("PRIV_ROLE")]) == ("Benign", "")


# --- discriminator sets / adjust -------------------------------------------------------------


def test_bounding_and_governance_sets_match_spec() -> None:
    """spec §policy.py discriminator classes."""
    assert BOUNDING == frozenset(
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
    assert GOVERNANCE == frozenset(
        {"managed_role", "issuer_token", "role_separated_cap"}
    )
    assert DECISIVE_MED == frozenset(
        {
            "HONEYPOT_LEGACY",
            "PONZI_SHAPE",
            "STRUCT_PROXY_EOA_ADMIN",
            "OWN_TX_ORIGIN",
        }
    )
    assert BOUNDING.isdisjoint(GOVERNANCE)
    assert "role_separated_cap" in GOVERNANCE
    assert "role_separated_cap" not in BOUNDING


def test_concealment_rules_are_high_base() -> None:
    """Concealment rules (HIGH-base) need no protection now. spec §policy.py."""
    for rule_id in _CONCEALMENT_HIGH_BASE:
        assert CATALOG[rule_id][1] == "HIGH"


def test_adjust_drop_returns_none() -> None:
    """DROP is the stronger form of INFO. spec §policy.py bounding class."""
    finding = _finding("BAL_DIRECT_SET", severity="HIGH", discriminators=("representation_switch",))
    assert adjust(finding) is None


def test_adjust_constant_cap_to_info() -> None:
    """Bounding → INFO. spec §policy.py bounding class."""
    finding = _finding("BAL_PRIV_MINT", severity="HIGH", discriminators=("constant_cap",))
    out = adjust(finding)
    assert out is not None
    assert out.severity == "INFO"
    assert out.base_severity == "HIGH"
    assert out.discriminators == ("constant_cap",)


def test_adjust_issuer_token_does_not_downgrade() -> None:
    """Governance is recorded only. spec §policy.py governance class."""
    finding = _finding("EXIT_ADDR_GATE", severity="HIGH", discriminators=("issuer_token",))
    out = adjust(finding)
    assert out is not None
    assert out.severity == "HIGH"


def test_adjust_fee_cap_wins_over_managed_role() -> None:
    """Bounding wins over governance. spec §policy.py (c)."""
    finding = _finding(
        "FEE_UNBOUNDED",
        severity="HIGH",
        discriminators=("managed_role", "fee_cap"),
    )
    out = adjust(finding)
    assert out is not None
    assert out.severity == "INFO"


def test_adjust_unmatched_discriminator_unchanged_severity() -> None:
    finding = _finding("EXIT_ADDR_GATE", severity="HIGH", discriminators=("eq_self",))
    out = adjust(finding)
    assert out is not None
    assert out.severity == "HIGH"


def test_finalize_managed_role_stays_high() -> None:
    """managed_role no longer downgrades. spec §policy.py governance class."""
    finding = _finding("EXIT_ADDR_GATE", severity="HIGH", discriminators=("managed_role",))
    adjusted = finalize([finding])
    assert len(adjusted) == 1
    assert adjusted[0].severity == "HIGH"
    assert decide(adjusted) == ("Malicious", "")


def test_finalize_concealment_rule_stays_high_with_governance() -> None:
    """Concealment rules (HIGH-base) stay HIGH; managed_role does not downgrade the other finding."""
    hidden = _finding("OWN_HIDDEN_ROLE", severity="HIGH")
    gated = _finding("EXIT_ADDR_GATE", severity="HIGH", discriminators=("managed_role",))
    adjusted = finalize([hidden, gated])
    assert {f.rule_id: f.severity for f in adjusted} == {
        "OWN_HIDDEN_ROLE": "HIGH",
        "EXIT_ADDR_GATE": "HIGH",
    }


def test_finalize_two_step_handoff_drops() -> None:
    finding = _finding("OWN_FAKE_RENOUNCE", severity="HIGH", discriminators=("two_step_handoff",))
    assert finalize([finding]) == []


def test_finalize_drop() -> None:
    finding = _finding("BAL_DIRECT_SET", severity="HIGH", discriminators=("representation_switch",))
    assert finalize([finding]) == []


def test_finalize_no_expiry_stays_high() -> None:
    """EXIT_TIME_GATE + no_expiry is already HIGH and stays counting. spec §policy.py."""
    finding = _finding(
        "EXIT_TIME_GATE",
        severity="HIGH",
        base_severity="MED",
        discriminators=("no_expiry", "managed_role"),
    )
    adjusted = finalize([finding])
    assert len(adjusted) == 1
    assert adjusted[0].severity == "HIGH"
    assert decide(adjusted) == ("Malicious", "")


def test_priv_role_stays_info() -> None:
    adjusted = finalize([_finding("PRIV_ROLE")])
    assert adjusted[0].severity == "INFO"


@pytest.mark.parametrize("rule_id", sorted(CATALOG))
@pytest.mark.parametrize("disc", _ALL_DISCS)
def test_catalog_times_discriminators_severity_and_reason(rule_id: str, disc: str) -> None:
    """Every catalog id × discriminator: severity class and reason are closed. spec §policy.py (k)."""
    finding = _finding(rule_id, discriminators=(disc,))
    if rule_id == "EXIT_TIME_GATE" and disc == "no_expiry":
        finding = _finding(rule_id, severity="HIGH", base_severity="MED", discriminators=(disc,))
    adjusted = finalize([finding])
    verdict, reason = decide(adjusted)
    assert reason in {"", "external_dependency"}
    assert verdict in {"Malicious", "Uncertain", "Benign"}
    if disc in _DROP:
        assert adjusted == []
        assert (verdict, reason) == ("Benign", "")
        return
    assert len(adjusted) == 1
    assert adjusted[0].severity in {"HIGH", "MED", "INFO"}
    if adjusted[0].severity == "MED":
        assert adjusted[0].rule_id == "STRUCT_EXTERNAL_GATE"


def test_governance_and_bounding_notes() -> None:
    finding = _finding(
        "BAL_PRIV_MINT",
        severity="HIGH",
        discriminators=("constant_cap", "managed_role", "role_separated_cap"),
    )
    assert governance_notes(finding) == [
        GOVERNANCE_NOTE["managed_role"],
        GOVERNANCE_NOTE["role_separated_cap"],
    ]
    assert bounding_notes(finding) == [BOUNDING_NOTE["constant_cap"]]
    assert set(GOVERNANCE_NOTE) == GOVERNANCE
    assert set(BOUNDING_NOTE) == BOUNDING


# --- corpus: file verdicts (DT-5, DT-14) -----------------------------------------------------


def _file_verdict(path: Path, rel: str) -> dict:
    return _analyze_in_process(str(path), rel)


@pytest.mark.parametrize(
    "rule_id",
    (
        "BAL_PRIV_MINT",
        "EXIT_GLOBAL_SWITCH",
        "EXIT_AMOUNT_LIMIT",
        "LEAK_PRIV_SWEEP",
        "FEE_UNBOUNDED",
    ),
)
def test_tier1_bounded_ben_is_benign(rule_id: str) -> None:
    """Bounded Tier 1 ben twins → Benign. spec §policy.py corpus consequences."""
    path = tier1_sol(rule_id, "ben")
    result = _file_verdict(path, f"{rule_id}/ben/{path.name}")
    assert result["verdict"] == "Benign", result


@pytest.mark.parametrize(
    ("folder", "filename"),
    (
        ("oz_ownable2step_token", "OzTwoStepToken.sol"),
        ("timelock_self_call", "MiniTimelock.sol"),
        ("oz_ownable_fee_capped", "OzFeeCapped.sol"),
    ),
)
def test_harness_bounded_is_benign(folder: str, filename: str) -> None:
    """Two-step / self-call / fee-cap harnesses → Benign. spec §policy.py."""
    path = HARNESS / folder / filename
    result = _file_verdict(path, f"_harness/{folder}/{filename}")
    assert result["verdict"] == "Benign", result


@pytest.mark.parametrize(
    ("folder", "filename"),
    (
        ("oz_ownable_rug", "OzOwnableRug.sol"),
        ("trading_switch_owner_bypass", "TradingSwitchBypass.sol"),
        ("oz_accesscontrol_blacklist", "OzRoleBlacklist.sol"),
    ),
)
def test_harness_asymmetric_is_malicious(folder: str, filename: str) -> None:
    """Asymmetric / unbounded harnesses → Malicious. spec §policy.py."""
    path = HARNESS / folder / filename
    result = _file_verdict(path, f"_harness/{folder}/{filename}")
    assert result["verdict"] == "Malicious", result


_TIER3_BOUNDED = (
    ("oz_erc20_pausable_ownable", "OzErc20PausableOwnable.sol"),
    ("oz_erc20capped_accesscontrol", "OzErc20CappedAccessControl.sol"),
    ("oz_erc20permit", "OzErc20Permit.sol"),
    ("reflection_token", "ReflectionToken.sol"),
    ("erc20_foreign_rescue", "Erc20ForeignRescue.sol"),
)


@pytest.mark.parametrize(("folder", "filename"), _TIER3_BOUNDED)
def test_tier3_bounded_benign_zero_high(folder: str, filename: str) -> None:
    """DT-5 −1 brake: five bounded Tier 3 fixtures are Benign with zero HIGH."""
    path = TIER3 / folder / filename
    result = _file_verdict(path, f"{folder}/{filename}")
    highs = [f for f in result.get("findings") or [] if f.get("severity") == "HIGH"]
    assert result["verdict"] == "Benign", result
    assert highs == [], highs


@pytest.mark.parametrize(
    ("folder", "filename"),
    (
        ("usdc_fiattoken", "FiatTokenV1.sol"),
        ("bancor_smarttoken", "SmartToken.sol"),
    ),
)
def test_tier3_governance_is_malicious(folder: str, filename: str) -> None:
    """Governance-only fixtures count. spec §policy.py / DT-5."""
    path = TIER3 / folder / filename
    result = _file_verdict(path, f"{folder}/{filename}")
    assert result["verdict"] == "Malicious", result


def test_tier3_lido_is_uncertain_external_dependency() -> None:
    """INTENDED: Uncertain(external_dependency). spec §policy.py / DT-5."""
    path = TIER3 / "lido_ldo_minime" / "MiniMeToken.sol"
    result = _file_verdict(path, "lido_ldo_minime/MiniMeToken.sol")
    assert result["verdict"] == "Uncertain", result
    assert result.get("reason") == "external_dependency"


@pytest.mark.parametrize(
    ("stem", "want"),
    (
        ("P1_StandardToken", "Benign"),
        ("P2_HiddenMint", "Malicious"),
        ("P3_Honeypot", "Malicious"),
        ("P4_CappedMint", "Benign"),
        ("P5_DelegatecallBackdoor", "Malicious"),
    ),
)
def test_tier0_public_samples(stem: str, want: str) -> None:
    """DT-14: Tier 0 public samples match the organizers' labels."""
    folder = f"{stem}_sol"
    path = CASES / "tier0_judge" / folder / f"{folder}.sol"
    result = _file_verdict(path, f"{folder}/{folder}.sol")
    assert result["verdict"] == want, result
