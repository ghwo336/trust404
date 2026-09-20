"""Family C rules: FEE_ADDR_MUTABLE and the LEAK_* family."""

from __future__ import annotations

import yaml

from detector.engine import target_contracts
from detector.rules.family_c_leak import (
    RULES,
    fee_addr_mutable,
    leak_arbitrary_transferfrom,
    leak_exempt_path,
    leak_priv_sweep,
)
from tests.detector.analysis_util import make_ctx, tier1_ctx, tier3_ctx
from tests.detector.conftest import TIER1, TIER3

# transfer() that calls _update(msg.sender, …) makes Slither mark _update.from as
# sender-dependent, so _sender_key skips every debit and the seize control is dead.
# Mint/seize-only keeps the unified _update shape that OZ v5 actually leaks on.
_UNIFIED_UPDATE_SRC = """\
pragma solidity ^0.8.20;
error Bad();
contract U {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address o;
    function _update(address from, address to, uint256 v) internal {
        if (from == address(0)) { totalSupply += v; }
        else {
            uint256 fb = balanceOf[from];
            if (fb < v) revert Bad();
            balanceOf[from] = fb - v;
        }
        if (to == address(0)) { totalSupply -= v; }
        else { balanceOf[to] += v; }
    }
    function mint(address to, uint256 v) external {
        require(msg.sender == o);
        _update(address(0), to, v);
    }
    function seize(address from, uint256 v) external {
        require(msg.sender == o);
        _update(from, address(0), v);
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


def test_family_c_registry_exports_four_rules() -> None:
    assert RULES == [
        fee_addr_mutable,
        leak_arbitrary_transferfrom,
        leak_exempt_path,
        leak_priv_sweep,
    ]


def test_fee_addr_mutable_mal_fires_med_at_writer(slither_for) -> None:
    """Catalog base stays MED; finalize forces INFO (spec §policy.py)."""
    ctx = tier1_ctx(slither_for, "FEE_ADDR_MUTABLE", "mal")
    _assert_mal(fee_addr_mutable(ctx), "FEE_ADDR_MUTABLE", "MED")


def test_fee_addr_mutable_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "FEE_ADDR_MUTABLE", "ben")
    _assert_ben(fee_addr_mutable(ctx), "FEE_ADDR_MUTABLE")


def test_leak_arbitrary_transferfrom_mal_fires_high(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_ARBITRARY_TRANSFERFROM", "mal")
    _assert_mal(leak_arbitrary_transferfrom(ctx), "LEAK_ARBITRARY_TRANSFERFROM", "HIGH")


def test_leak_arbitrary_transferfrom_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_ARBITRARY_TRANSFERFROM", "ben")
    _assert_ben(leak_arbitrary_transferfrom(ctx), "LEAK_ARBITRARY_TRANSFERFROM")


def test_leak_arbitrary_transferfrom_silent_on_oz_erc20(slither_for) -> None:
    ctx = tier3_ctx(
        slither_for, "oz_erc20_pausable_ownable", "OzErc20PausableOwnable.sol", "OzErc20PausableOwnable"
    )
    assert leak_arbitrary_transferfrom(ctx) == []


def test_leak_arbitrary_transferfrom_skips_zero_address_mint(slither_for, tmp_path) -> None:
    src = tmp_path / "U.sol"
    src.write_text(_UNIFIED_UPDATE_SRC, encoding="utf-8")
    ctx = make_ctx(slither_for, src, "U")
    hits = [f for f in leak_arbitrary_transferfrom(ctx) if f.function == "mint"]
    assert hits == [], [(f.function, f.severity, f.reasoning) for f in hits]


def test_leak_arbitrary_transferfrom_fires_on_privileged_seize(slither_for, tmp_path) -> None:
    src = tmp_path / "U.sol"
    src.write_text(_UNIFIED_UPDATE_SRC, encoding="utf-8")
    ctx = make_ctx(slither_for, src, "U")
    hits = [f for f in leak_arbitrary_transferfrom(ctx) if f.function == "seize"]
    assert hits, "seize must keep firing LEAK_ARBITRARY_TRANSFERFROM"


def test_leak_exempt_path_mal_fires_high(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_EXEMPT_PATH", "mal")
    _assert_mal(leak_exempt_path(ctx), "LEAK_EXEMPT_PATH", "HIGH")


def test_leak_exempt_path_ben_silent(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_EXEMPT_PATH", "ben")
    _assert_ben(leak_exempt_path(ctx), "LEAK_EXEMPT_PATH")


def test_leak_priv_sweep_mal_fires_high(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_PRIV_SWEEP", "mal")
    _assert_mal(leak_priv_sweep(ctx), "LEAK_PRIV_SWEEP", "HIGH")


def test_leak_priv_sweep_ben_is_foreign_only(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_PRIV_SWEEP", "ben")
    findings = leak_priv_sweep(ctx)
    _assert_ben(findings, "LEAK_PRIV_SWEEP")
    for item in findings:
        assert "foreign_only" in item.discriminators


def test_family_c_tier3_high_findings_carry_downgrade(slither_for) -> None:
    highs: list[tuple[str, str, str, tuple[str, ...]]] = []
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
                highs.append((folder, item.rule_id, item.function, item.discriminators))
    assert isinstance(highs, list)
