"""Wave 4d policy/predicate amendments (2026-09-20)."""

from __future__ import annotations

from pathlib import Path

from detector.analysis import privilege
from detector.engine import _analyze_in_process
from tests.detector.analysis_util import fn, make_ctx
from tests.detector.conftest import CASES, HARNESS

TIER2 = CASES / "tier2_realworld"
DHE = (
    TIER2
    / "crpwarner"
    / "0x11CBC781DadAAD13fc3a361772C80B1C027820AF_sol"
    / "0x11CBC781DadAAD13fc3a361772C80B1C027820AF_sol.sol"
)
BASETOKEN = (
    TIER2
    / "crpwarner"
    / "0xD217Dc0cAB1C952a7cE6f4D7ca4549CdE1F37bb0_sol"
    / "0xD217Dc0cAB1C952a7cE6f4D7ca4549CdE1F37bb0_sol.sol"
)
MOON = (
    TIER2
    / "honeybadger"
    / "inheritance_disorder_0x9c0c5a14fde1306686a8a270f271165acda670c2_sol"
    / "inheritance_disorder_0x9c0c5a14fde1306686a8a270f271165acda670c2_sol.sol"
)


def _analyze(path: Path) -> dict:
    return _analyze_in_process(str(path), path.name)


def _high_ids(result: dict) -> set[str]:
    return {f["rule_id"] for f in result.get("findings") or [] if f.get("severity") == "HIGH"}


def _fns(result: dict, rule_id: str) -> set[str]:
    return {f["function"] for f in result.get("findings") or [] if f.get("rule_id") == rule_id}


def test_dhe_exit_addr_gate() -> None:
    result = _analyze(DHE)
    assert result["verdict"] == "Malicious"
    assert "EXIT_ADDR_GATE" in _high_ids(result)
    assert {"removeSniper", "_transfer"} <= _fns(result, "EXIT_ADDR_GATE")


def test_ether_to_the_moon_leak_priv_sweep() -> None:
    result = _analyze(MOON)
    assert result["verdict"] in {"Malicious", "Uncertain"}
    assert result["verdict"] != "Benign"
    assert "LEAK_PRIV_SWEEP" in {f["rule_id"] for f in result.get("findings") or []}


def test_basetoken_transfer_not_privileged(slither_for) -> None:
    ctx = make_ctx(slither_for, BASETOKEN, "BaseToken")
    transfer = fn(ctx, "transfer", sig="transfer(address,uint256)")
    assert privilege.is_privileged(transfer) is False
    result = _analyze(BASETOKEN)
    assert result["verdict"] == "Malicious"


def test_oz_ownable_rug_malicious_exit_addr_gate() -> None:
    result = _analyze(HARNESS / "oz_ownable_rug" / "OzOwnableRug.sol")
    assert result["verdict"] == "Malicious"
    assert "EXIT_ADDR_GATE" in _high_ids(result)


def test_timelock_no_d_family_high() -> None:
    result = _analyze(HARNESS / "timelock_self_call" / "MiniTimelock.sol")
    d_high = [
        f
        for f in result.get("findings") or []
        if f.get("severity") == "HIGH" and str(f.get("rule_id", "")).startswith("OWN_")
    ]
    assert d_high == [], d_high
    priv = [f for f in result.get("findings") or [] if f.get("rule_id") == "PRIV_ROLE"]
    assert any("eq_self" in (f.get("reasoning") or "") for f in priv)


def test_ownable2step_no_d_family_high() -> None:
    result = _analyze(HARNESS / "oz_ownable2step_token" / "OzTwoStepToken.sol")
    d_high = [
        f
        for f in result.get("findings") or []
        if f.get("severity") == "HIGH" and str(f.get("rule_id", "")).startswith("OWN_")
    ]
    assert d_high == [], d_high
    assert result["verdict"] in {"Benign", "Uncertain"}


def test_trading_switch_owner_bypass_malicious() -> None:
    result = _analyze(HARNESS / "trading_switch_owner_bypass" / "TradingSwitchBypass.sol")
    assert result["verdict"] == "Malicious"
    assert "EXIT_GLOBAL_SWITCH" in _high_ids(result)
    assert {"setTrading", "_transfer"} <= _fns(result, "EXIT_GLOBAL_SWITCH")
    bypass = [
        f
        for f in result.get("findings") or []
        if f.get("rule_id") == "EXIT_GLOBAL_SWITCH" and "exempt via" in (f.get("reasoning") or "")
    ]
    assert bypass, result.get("findings")
