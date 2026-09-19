"""Family F/G rules: drainers, honeypots, and ponzi shape."""

from __future__ import annotations

import yaml

from detector.engine import target_contracts
from detector.rules.family_fg import RULES, drain_approval_pull, honeypot_legacy, ponzi_shape
from tests.detector.analysis_util import make_ctx, tier1_ctx, tier3_ctx
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


def _expected_fns(rule_id: str) -> list[str]:
    return list(_labels(rule_id, "mal").get("expected_functions") or [])


def _accepted(rule_id: str, twin: str) -> list[str]:
    return list(_labels(rule_id, twin).get("accepted_verdicts") or [])


def _tier3_ctxs(slither_for):
    out = []
    for folder, filename in _TIER3:
        path = TIER3 / folder / filename
        slither = slither_for(path)
        for contract in target_contracts(slither, path):
            out.append((folder, make_ctx(slither_for, path, contract.name)))
    return out


def _assert_mal(findings, rule_id: str, severity: str) -> None:
    matched = [f for f in findings if f.rule_id == rule_id]
    assert matched, f"{rule_id} produced no findings"
    expected = set(_expected_fns(rule_id))
    assert any(f.severity == severity and f.function in expected for f in matched), (
        rule_id,
        [(f.function, f.severity) for f in matched],
        expected,
    )
    for item in matched:
        assert item.contract
        assert item.function
        assert item.lines
        assert item.reasoning


def _assert_ben(findings, rule_id: str) -> None:
    matched = [f for f in findings if f.rule_id == rule_id]
    accepted = _accepted(rule_id, "ben")
    if accepted == ["Benign"]:
        assert matched == [], [(f.function, f.severity, f.discriminators) for f in matched]
        return
    for item in matched:
        if item.severity == "HIGH":
            assert _DOWNGRADE.intersection(item.discriminators), (
                rule_id,
                item.function,
                item.severity,
                item.discriminators,
            )


def test_family_fg_registry_exports_three_rules() -> None:
    assert RULES == [drain_approval_pull, honeypot_legacy, ponzi_shape]


def test_drain_approval_pull_mal_fires_high(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "DRAIN_APPROVAL_PULL", "mal")
    _assert_mal(drain_approval_pull(ctx), "DRAIN_APPROVAL_PULL", "HIGH")


def test_drain_approval_pull_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "DRAIN_APPROVAL_PULL", "ben")
    _assert_ben(drain_approval_pull(ctx), "DRAIN_APPROVAL_PULL")


def test_drain_approval_pull_silent_on_oz_permit(slither_for) -> None:
    ctx = tier3_ctx(slither_for, "oz_erc20permit", "OzErc20Permit.sol", "OzErc20Permit")
    assert drain_approval_pull(ctx) == []


def test_honeypot_legacy_mal_fires_med(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "HONEYPOT_LEGACY", "mal")
    _assert_mal(honeypot_legacy(ctx), "HONEYPOT_LEGACY", "MED")


def test_honeypot_legacy_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "HONEYPOT_LEGACY", "ben")
    _assert_ben(honeypot_legacy(ctx), "HONEYPOT_LEGACY")


def test_ponzi_shape_mal_fires_med(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "PONZI_SHAPE", "mal")
    _assert_mal(ponzi_shape(ctx), "PONZI_SHAPE", "MED")


def test_ponzi_shape_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "PONZI_SHAPE", "ben")
    _assert_ben(ponzi_shape(ctx), "PONZI_SHAPE")


def test_family_fg_tier3_high_findings_carry_downgrade(slither_for) -> None:
    for folder, ctx in _tier3_ctxs(slither_for):
        for rule in RULES:
            for item in rule(ctx):
                if item.severity != "HIGH":
                    continue
                assert _DOWNGRADE.intersection(item.discriminators), (
                    folder,
                    ctx.contract.name,
                    item.rule_id,
                    item.function,
                    item.discriminators,
                )
