"""Family E rules: structural escape hatches."""

from __future__ import annotations

import yaml

from detector.analysis.context import ContractContext
from detector.compile import compile_file
from detector.engine import target_contracts
from detector.rules.family_e_struct import (
    RULES,
    struct_delegatecall_settable,
    struct_external_gate,
    struct_proxy_eoa_admin,
    struct_selfdestruct,
)
from tests.detector.analysis_util import make_ctx, tier1_ctx
from tests.detector.conftest import CASES, TIER1, TIER3

# Captured from current Family E output on STRUCT_PROXY_EOA_ADMIN (git stash
# comparison against this branch, 2026-09-20): only the proxy-admin rule at MED
# on mal; ben silent; STRUCT_DELEGATECALL_SETTABLE does not fire on either twin.
_PROXY_EOA_ADMIN_BASELINE = {
    "mal": {("STRUCT_PROXY_EOA_ADMIN", "MED")},
    "ben": set(),
}

_UNPRIVILEGED_PARAM_DELEGATECALL = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract OpenDelegate {
    function run(address target, bytes calldata data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}
"""

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


def test_family_e_registry_exports_four_rules() -> None:
    assert RULES == [
        struct_external_gate,
        struct_delegatecall_settable,
        struct_selfdestruct,
        struct_proxy_eoa_admin,
    ]


def test_struct_external_gate_mal_fires_med(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_EXTERNAL_GATE", "mal")
    _assert_mal(struct_external_gate(ctx), "STRUCT_EXTERNAL_GATE", "MED")


def test_struct_external_gate_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_EXTERNAL_GATE", "ben")
    _assert_ben(struct_external_gate(ctx), "STRUCT_EXTERNAL_GATE")


def test_struct_delegatecall_settable_mal_fires_high(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_DELEGATECALL_SETTABLE", "mal")
    findings = struct_delegatecall_settable(ctx)
    _assert_mal(findings, "STRUCT_DELEGATECALL_SETTABLE", "HIGH")
    names = {f.function for f in findings}
    assert "exec" in names
    assert "setImpl" in names


def test_struct_delegatecall_settable_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_DELEGATECALL_SETTABLE", "ben")
    _assert_ben(struct_delegatecall_settable(ctx), "STRUCT_DELEGATECALL_SETTABLE")


def test_struct_delegatecall_skips_proxy_fallback(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_PROXY_EOA_ADMIN", "mal")
    assert struct_delegatecall_settable(ctx) == []


def test_struct_delegatecall_settable_p5_param_target_fires_high(slither_for) -> None:
    path = (
        CASES
        / "tier0_judge"
        / "P5_DelegatecallBackdoor_sol"
        / "P5_DelegatecallBackdoor_sol.sol"
    )
    ctx = make_ctx(slither_for, path)
    findings = struct_delegatecall_settable(ctx)
    matched = [
        f
        for f in findings
        if f.rule_id == "STRUCT_DELEGATECALL_SETTABLE"
        and f.severity == "HIGH"
        and f.function == "execute"
        and 37 in f.lines
    ]
    assert matched, [(f.function, f.severity, f.lines, f.reasoning) for f in findings]
    reasoning = matched[0].reasoning
    assert "execute" in reasoning
    assert "parameter" in reasoning.lower()
    assert "privileged" in reasoning.lower()


def test_struct_delegatecall_settable_unprivileged_param_silent(tmp_path) -> None:
    src = tmp_path / "OpenDelegate.sol"
    src.write_text(_UNPRIVILEGED_PARAM_DELEGATECALL, encoding="utf-8")
    slither = compile_file(src)
    contracts = target_contracts(slither, src)
    assert contracts
    ctx = ContractContext(slither=slither, contract=contracts[0], input_root=src.parent)
    findings = struct_delegatecall_settable(ctx)
    assert findings == [], [(f.function, f.severity, f.reasoning) for f in findings]


def test_struct_proxy_eoa_admin_outputs_unchanged(slither_for) -> None:
    for twin, expected in _PROXY_EOA_ADMIN_BASELINE.items():
        ctx = tier1_ctx(slither_for, "STRUCT_PROXY_EOA_ADMIN", twin)
        got = {(item.rule_id, item.severity) for rule in RULES for item in rule(ctx)}
        assert got == expected, (twin, got, expected)


def test_struct_selfdestruct_mal_fires_high(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_SELFDESTRUCT", "mal")
    _assert_mal(struct_selfdestruct(ctx), "STRUCT_SELFDESTRUCT", "HIGH")


def test_struct_selfdestruct_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_SELFDESTRUCT", "ben")
    _assert_ben(struct_selfdestruct(ctx), "STRUCT_SELFDESTRUCT")


def test_struct_proxy_eoa_admin_mal_fires_med(slither_for) -> None:
    """Catalog base stays MED; finalize lifts DECISIVE_MED to HIGH (spec §policy.py)."""
    ctx = tier1_ctx(slither_for, "STRUCT_PROXY_EOA_ADMIN", "mal")
    _assert_mal(struct_proxy_eoa_admin(ctx), "STRUCT_PROXY_EOA_ADMIN", "MED")


def test_struct_proxy_eoa_admin_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "STRUCT_PROXY_EOA_ADMIN", "ben")
    _assert_ben(struct_proxy_eoa_admin(ctx), "STRUCT_PROXY_EOA_ADMIN")


def test_family_e_tier3_high_findings_carry_downgrade(slither_for) -> None:
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
