"""Role / issuer / custody / ungate predicates."""

from __future__ import annotations

from detector.analysis import roles
from detector.analysis.privilege import auth_vars
from tests.detector.analysis_util import fn, svar, tier1_ctx, tier3_ctx


def _bool_end(ctx, var_name: str):
    for end in ctx.end_nodes:
        reads = " ".join(v.name for v in end.node.state_variables_read)
        expr = str(end.node.expression or "")
        if var_name in reads or var_name in expr or "paused" in expr or "transfersEnabled" in expr:
            if end.kind in ("require", "assert", "if_revert"):
                return end
    raise AssertionError(f"no end node for {var_name}: {[(e.kind, e.node.expression) for e in ctx.end_nodes]}")


def test_ungate_exists(slither_for) -> None:
    mal = tier1_ctx(slither_for, "EXIT_GLOBAL_SWITCH", "mal")
    paused = svar(mal, "paused")
    end = _bool_end(mal, "paused")
    assert roles.ungate_exists(mal, paused, end) is False

    ben = tier1_ctx(slither_for, "EXIT_GLOBAL_SWITCH", "ben")
    paused_oz = svar(ben, "_paused")
    end_b = _bool_end(ben, "_paused")
    assert roles.ungate_exists(ben, paused_oz, end_b) is True

    bancor = tier3_ctx(slither_for, "bancor_smarttoken", "SmartToken.sol", "SmartToken")
    enabled = svar(bancor, "transfersEnabled")
    end_c = _bool_end(bancor, "transfersEnabled")
    assert roles.ungate_exists(bancor, enabled, end_c) is True


def test_issuer_token(slither_for) -> None:
    bancor = tier3_ctx(slither_for, "bancor_smarttoken", "SmartToken.sol", "SmartToken")
    assert roles.issuer_token(bancor) is True
    mint = tier1_ctx(slither_for, "BAL_PRIV_MINT", "mal")
    assert roles.issuer_token(mint) is False


def test_managed_role(slither_for) -> None:
    usdc = tier3_ctx(slither_for, "usdc_fiattoken", "FiatTokenV1.sol", "FiatTokenV1")
    assert roles.managed_role(usdc, svar(usdc, "blacklister")) is True
    gate = tier1_ctx(slither_for, "EXIT_ADDR_GATE", "mal")
    assert roles.managed_role(gate, svar(gate, "owner")) is False


def test_library_role(slither_for) -> None:
    ben = tier1_ctx(slither_for, "PRIV_ROLE", "ben")
    assert roles.library_role(ben, fn(ben, "setBlacklist")) is True
    mal = tier1_ctx(slither_for, "PRIV_ROLE", "mal")
    assert roles.library_role(mal, fn(mal, "setBlacklist")) is False


def test_one_shot_initializer(slither_for) -> None:
    mal = tier1_ctx(slither_for, "OWN_REASSIGN_NONSTD", "mal")
    assert roles.one_shot_initializer(fn(mal, "initialize")) is False
    usdc = tier3_ctx(slither_for, "usdc_fiattoken", "FiatTokenV1.sol", "FiatTokenV1")
    assert roles.one_shot_initializer(fn(usdc, "initialize")) is True


def test_has_custody(slither_for) -> None:
    mal = tier1_ctx(slither_for, "LEAK_PRIV_SWEEP", "mal")
    assert roles.has_custody(mal) is True
    ben = tier1_ctx(slither_for, "LEAK_PRIV_SWEEP", "ben")
    assert roles.has_custody(ben) is False
    minime = tier3_ctx(slither_for, "lido_ldo_minime", "MiniMeToken.sol", "MiniMeToken")
    assert roles.has_custody(minime) is False
