"""SLITHER_HIGH_OVERLAY: Slither built-in High-impact detectors as INFO findings."""

from __future__ import annotations

import yaml

from detector.engine import _analyze_in_process, target_contracts
from detector.rules.overlay import EXPLOIT_SHAPE_CHECKS, RULES, slither_high_overlay
from tests.detector.analysis_util import make_ctx, tier1_ctx
from tests.detector.conftest import TIER1, TIER3, tier1_sol

_DOWNGRADE = frozenset(
    {"foreign_only", "no_custody", "issuer_token", "managed_role"}
)

_TIER3 = (
    ("bancor_smarttoken", "SmartToken.sol"),
    ("erc20_foreign_rescue", "Erc20ForeignRescue.sol"),
    ("lido_ldo_minime", "MiniMeToken.sol"),
    ("oz_erc20_pausable_ownable", "OzErc20PausableOwnable.sol"),
    ("oz_erc20capped_accesscontrol", "OzErc20CappedAccessControl.sol"),
    ("oz_erc20permit", "OzErc20Permit.sol"),
    ("reflection_token", "ReflectionToken.sol"),
    ("usdc_fiattoken", "FiatTokenV1.sol"),
)


def _labels(rule_id: str, twin: str) -> dict:
    return yaml.safe_load((TIER1 / rule_id / twin / "labels.yaml").read_text(encoding="utf-8"))


def test_overlay_registry_exports_one_rule() -> None:
    assert RULES == [slither_high_overlay]


def test_exploit_shape_checks_match_spec() -> None:
    """spec §policy.py counting finding: exploit-shape set (no loop/rtlo/protected-vars)."""
    assert EXPLOIT_SHAPE_CHECKS == frozenset(
        {
            "reentrancy-eth",
            "arbitrary-send-eth",
            "arbitrary-send-erc20",
            "arbitrary-send-erc20-permit",
            "suicidal",
            "controlled-delegatecall",
            "unprotected-upgrade",
        }
    )


def test_slither_high_overlay_mal_fires_info_on_withdraw(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "SLITHER_HIGH_OVERLAY", "mal")
    findings = slither_high_overlay(ctx)
    expected = set(_labels("SLITHER_HIGH_OVERLAY", "mal").get("expected_functions") or [])
    matched = [f for f in findings if f.rule_id == "SLITHER_HIGH_OVERLAY"]
    assert matched
    assert any(f.severity == "INFO" and f.function in expected for f in matched), [
        (f.function, f.severity, f.reasoning) for f in matched
    ]
    for item in matched:
        assert item.contract == ctx.contract.name
        assert item.function
        assert item.lines
        assert item.reasoning
        assert ":" in item.reasoning


def test_slither_high_overlay_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "SLITHER_HIGH_OVERLAY", "ben")
    assert slither_high_overlay(ctx) == []


def test_slither_high_overlay_is_memoized(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "SLITHER_HIGH_OVERLAY", "mal")
    first = slither_high_overlay(ctx)
    second = slither_high_overlay(ctx)
    assert first == second
    assert hasattr(ctx.slither, "_t404_slither_high_overlay")


def test_drain_ben_overlay_is_evidence_only(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "DRAIN_APPROVAL_PULL", "ben")
    findings = slither_high_overlay(ctx)
    assert findings
    assert all("evidence_only" in item.discriminators for item in findings), [
        (item.reasoning, item.discriminators) for item in findings
    ]


def test_overlay_mal_reentrancy_is_not_evidence_only(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "SLITHER_HIGH_OVERLAY", "mal")
    findings = slither_high_overlay(ctx)
    reentrancy = [item for item in findings if item.reasoning.startswith("reentrancy-eth")]
    assert reentrancy
    assert all("evidence_only" not in item.discriminators for item in reentrancy)


def test_engine_verdicts_for_overlay_pairs() -> None:
    drain = _analyze_in_process(
        str(tier1_sol("DRAIN_APPROVAL_PULL", "ben")),
        "DRAIN_APPROVAL_PULL/ben/ben.sol",
    )
    assert drain["verdict"] == "Benign", drain

    leak = _analyze_in_process(
        str(tier1_sol("LEAK_PRIV_SWEEP", "ben")),
        "LEAK_PRIV_SWEEP/ben/ben.sol",
    )
    assert leak["verdict"] == "Benign", leak

    mal = _analyze_in_process(
        str(tier1_sol("SLITHER_HIGH_OVERLAY", "mal")),
        "SLITHER_HIGH_OVERLAY/mal/mal.sol",
    )
    # spec §policy.py: exploit-shape overlay without evidence_only is a counting finding
    assert mal["verdict"] == "Malicious", mal
    assert mal.get("reason", "") == ""


def test_overlay_reasoning_has_no_path(slither_for) -> None:
    pairs = (
        ("DRAIN_APPROVAL_PULL", "ben"),
        ("LEAK_PRIV_SWEEP", "ben"),
        ("SLITHER_HIGH_OVERLAY", "mal"),
    )
    for rule_id, twin in pairs:
        ctx = tier1_ctx(slither_for, rule_id, twin)
        for item in slither_high_overlay(ctx):
            assert "/" not in item.reasoning, item.reasoning
            assert ".bench_work" not in item.reasoning, item.reasoning
            assert item.reasoning.split(":", 1)[0]


def test_overlay_tier3_high_findings_carry_downgrade(slither_for) -> None:
    for folder, filename in _TIER3:
        path = TIER3 / folder / filename
        slither = slither_for(path)
        for contract in target_contracts(slither, path):
            ctx = make_ctx(slither_for, path, contract.name)
            for item in slither_high_overlay(ctx):
                assert item.severity == "INFO"
                if item.severity == "HIGH":
                    assert _DOWNGRADE.intersection(item.discriminators), (
                        folder,
                        contract.name,
                        item.function,
                        item.discriminators,
                    )
