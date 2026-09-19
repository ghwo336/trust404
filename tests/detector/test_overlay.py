"""SLITHER_HIGH_OVERLAY: Slither built-in High-impact detectors as INFO findings."""

from __future__ import annotations

import yaml

from detector.engine import target_contracts
from detector.rules.overlay import RULES, slither_high_overlay
from tests.detector.analysis_util import make_ctx, tier1_ctx
from tests.detector.conftest import TIER1, TIER3

_DOWNGRADE = frozenset(
    {"foreign_only", "no_custody", "issuer_token", "managed_role", "library_role"}
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
