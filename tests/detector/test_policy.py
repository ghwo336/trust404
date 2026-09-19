"""Policy verdict table and discriminator adjustment (hand-built Findings only)."""

from __future__ import annotations

from detector.model import Finding
from detector.policy import (
    BOUND_DISCRIMINATORS,
    CONCEALMENT_RULES,
    DOWNGRADE_TABLE,
    SHAPE_DISCRIMINATORS,
    adjust,
    decide,
    finalize,
)


def _finding(
    rule_id: str,
    *,
    family: str,
    severity: str,
    counts_for_escalation: bool = True,
    discriminators: tuple[str, ...] = (),
    base_severity: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        family=family,
        severity=severity,
        base_severity=base_severity or severity,
        discriminators=discriminators,
        counts_for_escalation=counts_for_escalation,
    )


def test_high_is_malicious() -> None:
    findings = [_finding("EXIT_ADDR_GATE", family="A", severity="HIGH")]
    assert decide(findings) == ("Malicious", "")


def test_high_beats_external_gate() -> None:
    findings = [
        _finding("EXIT_ADDR_GATE", family="A", severity="HIGH"),
        _finding("STRUCT_EXTERNAL_GATE", family="E", severity="MED"),
    ]
    assert decide(findings) == ("Malicious", "")


def test_external_gate_is_uncertain() -> None:
    findings = [_finding("STRUCT_EXTERNAL_GATE", family="E", severity="MED")]
    assert decide(findings) == ("Uncertain", "external_dependency")


def test_external_gate_blocks_escalation() -> None:
    findings = [
        _finding("STRUCT_EXTERNAL_GATE", family="E", severity="MED"),
        _finding("OWN_TX_ORIGIN", family="D", severity="MED"),
        _finding("HONEYPOT_LEGACY", family="F", severity="MED"),
    ]
    assert decide(findings) == ("Uncertain", "external_dependency")


def test_escalation_two_native_meds_two_families() -> None:
    findings = [
        _finding("OWN_TX_ORIGIN", family="D", severity="MED"),
        _finding("HONEYPOT_LEGACY", family="F", severity="MED"),
    ]
    assert decide(findings) == ("Malicious", "escalated:HONEYPOT_LEGACY,OWN_TX_ORIGIN")


def test_no_escalation_same_family() -> None:
    findings = [
        _finding("OWN_TX_ORIGIN", family="D", severity="MED"),
        _finding("OWN_TX_ORIGIN_2", family="D", severity="MED"),
    ]
    assert decide(findings) == ("Uncertain", "med_findings")


def test_no_escalation_duplicate_rule_id() -> None:
    findings = [
        _finding("OWN_TX_ORIGIN", family="D", severity="MED"),
        _finding("OWN_TX_ORIGIN", family="D", severity="MED"),
        _finding("HONEYPOT_LEGACY", family="F", severity="MED", counts_for_escalation=False),
    ]
    assert decide(findings) == ("Uncertain", "med_findings")


def test_no_escalation_for_bound_downgraded_meds() -> None:
    findings = [
        _finding("EXIT_ADDR_GATE", family="A", severity="MED", counts_for_escalation=False),
        _finding("BAL_PRIV_MINT", family="B", severity="MED", counts_for_escalation=False),
    ]
    assert decide(findings) == ("Uncertain", "med_findings")


def test_suppress_escalation_flag() -> None:
    findings = [
        _finding("OWN_TX_ORIGIN", family="D", severity="MED"),
        _finding("HONEYPOT_LEGACY", family="F", severity="MED"),
    ]
    assert decide(findings, suppress_escalation=True) == ("Uncertain", "med_findings")


def test_shape_discriminator_suppresses_escalation() -> None:
    findings = [
        _finding("OWN_TX_ORIGIN", family="D", severity="MED"),
        _finding("HONEYPOT_LEGACY", family="F", severity="MED"),
        _finding(
            "EXIT_ADDR_GATE",
            family="A",
            severity="MED",
            counts_for_escalation=False,
            discriminators=("managed_role",),
        ),
    ]
    assert decide(findings) == ("Uncertain", "med_findings")


def test_any_med_is_uncertain() -> None:
    findings = [_finding("OWN_TX_ORIGIN", family="D", severity="MED")]
    assert decide(findings) == ("Uncertain", "med_findings")


def test_slither_high_overlay_is_uncertain() -> None:
    findings = [_finding("SLITHER_HIGH_OVERLAY", family="C", severity="INFO")]
    assert decide(findings) == ("Uncertain", "slither_high")


def test_slither_high_evidence_only_does_not_lift() -> None:
    evidence = _finding(
        "SLITHER_HIGH_OVERLAY",
        family="C",
        severity="INFO",
        discriminators=("evidence_only",),
    )
    assert decide([evidence]) == ("Benign", "")
    exploit = _finding("SLITHER_HIGH_OVERLAY", family="C", severity="INFO")
    assert decide([exploit]) == ("Uncertain", "slither_high")


def test_info_only_is_benign() -> None:
    findings = [_finding("PRIV_ROLE", family="A", severity="INFO")]
    assert decide(findings) == ("Benign", "")


def test_empty_is_benign() -> None:
    assert decide([]) == ("Benign", "")


def test_concealment_rules_and_discriminator_sets() -> None:
    assert CONCEALMENT_RULES == frozenset(
        {
            "OWN_HIDDEN_ROLE",
            "OWN_FAKE_RENOUNCE",
            "VIEW_CALLER_DEPENDENT",
            "BAL_TRANSFER_HIDDEN_MINT",
            "LEAK_EXEMPT_PATH",
            "EXIT_CALLBACK_CYCLE",
        }
    )
    assert BOUND_DISCRIMINATORS == frozenset(
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
    assert SHAPE_DISCRIMINATORS == frozenset(
        {
            "managed_role",
            "issuer_token",
        }
    )


def test_adjust_concealed_leaves_finding_unchanged() -> None:
    finding = _finding(
        "EXIT_ADDR_GATE",
        family="A",
        severity="HIGH",
        discriminators=("managed_role",),
    )
    out = adjust(finding, concealed=True, downgrade_to={"managed_role": "MED"})
    assert out is finding


def test_adjust_drop_returns_none() -> None:
    finding = _finding(
        "BAL_DIRECT_SET",
        family="B",
        severity="HIGH",
        discriminators=("representation_switch",),
    )
    assert adjust(finding, concealed=False, downgrade_to={"representation_switch": "DROP"}) is None


def test_adjust_bound_downgrade_clears_escalation() -> None:
    finding = _finding(
        "BAL_PRIV_MINT",
        family="B",
        severity="HIGH",
        discriminators=("constant_cap",),
    )
    out = adjust(finding, concealed=False, downgrade_to={"constant_cap": "MED"})
    assert out is not None
    assert out.severity == "MED"
    assert out.base_severity == "HIGH"
    assert out.counts_for_escalation is False


def test_adjust_shape_downgrade_clears_escalation() -> None:
    finding = _finding(
        "EXIT_ADDR_GATE",
        family="A",
        severity="HIGH",
        discriminators=("issuer_token",),
    )
    out = adjust(finding, concealed=False, downgrade_to={"issuer_token": "MED"})
    assert out is not None
    assert out.severity == "MED"
    assert out.counts_for_escalation is False


def test_adjust_strongest_downgrade_wins() -> None:
    finding = _finding(
        "FEE_UNBOUNDED",
        family="A",
        severity="HIGH",
        discriminators=("managed_role", "fee_cap"),
    )
    out = adjust(
        finding,
        concealed=False,
        downgrade_to={"managed_role": "MED", "fee_cap": "INFO"},
    )
    assert out is not None
    assert out.severity == "INFO"
    assert out.counts_for_escalation is False


def test_adjust_native_med_keeps_escalation() -> None:
    finding = _finding(
        "OWN_TX_ORIGIN",
        family="D",
        severity="MED",
        base_severity="MED",
        discriminators=(),
    )
    out = adjust(finding, concealed=False, downgrade_to={"managed_role": "MED"})
    assert out is finding or (out is not None and out.counts_for_escalation is True)


def test_adjust_unmatched_discriminator_unchanged() -> None:
    finding = _finding(
        "EXIT_ADDR_GATE",
        family="A",
        severity="HIGH",
        discriminators=("not_a_real_disc",),
    )
    out = adjust(finding, concealed=False, downgrade_to={"managed_role": "MED"})
    assert out is finding


def test_downgrade_table_matches_spec() -> None:
    assert DOWNGRADE_TABLE == {
        "ungate_exists": "MED",
        "constant_floor": "MED",
        "bounded_window": "MED",
        "constant_cap": "MED",
        "role_separated_cap": "MED",
        "fee_cap": "INFO",
        "foreign_only": "INFO",
        "no_custody": "MED",
        "managed_role": "MED",
        "issuer_token": "MED",
        "representation_switch": "DROP",
        "one_shot_initializer": "DROP",
        "two_step_handoff": "DROP",
    }


def test_finalize_managed_role_high_to_med() -> None:
    finding = _finding(
        "EXIT_ADDR_GATE",
        family="A",
        severity="HIGH",
        base_severity="HIGH",
        discriminators=("managed_role",),
    )
    adjusted, shape_applied = finalize([finding])
    assert shape_applied is True
    assert len(adjusted) == 1
    assert adjusted[0].severity == "MED"
    assert adjusted[0].counts_for_escalation is False


def test_finalize_concealment_blocks_downgrade() -> None:
    hidden = _finding(
        "OWN_HIDDEN_ROLE",
        family="D",
        severity="HIGH",
        base_severity="HIGH",
    )
    gated = _finding(
        "EXIT_ADDR_GATE",
        family="A",
        severity="HIGH",
        base_severity="HIGH",
        discriminators=("managed_role",),
    )
    adjusted, _shape = finalize([hidden, gated])
    assert {f.rule_id: f.severity for f in adjusted} == {
        "OWN_HIDDEN_ROLE": "HIGH",
        "EXIT_ADDR_GATE": "HIGH",
    }


def test_finalize_two_step_handoff_drops() -> None:
    finding = _finding(
        "OWN_FAKE_RENOUNCE",
        family="D",
        severity="HIGH",
        base_severity="HIGH",
        discriminators=("two_step_handoff",),
    )
    adjusted, shape_applied = finalize([finding])
    assert adjusted == []
    assert shape_applied is False


def test_finalize_drop() -> None:
    finding = _finding(
        "BAL_DIRECT_SET",
        family="B",
        severity="HIGH",
        base_severity="HIGH",
        discriminators=("representation_switch",),
    )
    adjusted, shape_applied = finalize([finding])
    assert adjusted == []
    assert shape_applied is False


def test_finalize_no_expiry_not_downgraded() -> None:
    finding = _finding(
        "EXIT_TIME_GATE",
        family="A",
        severity="HIGH",
        base_severity="MED",
        discriminators=("no_expiry", "managed_role"),
    )
    adjusted, shape_applied = finalize([finding])
    assert len(adjusted) == 1
    assert adjusted[0].severity == "HIGH"
    assert adjusted[0] is finding or adjusted[0].severity == "HIGH"
    assert shape_applied is True

