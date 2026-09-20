"""Family B rule recall on Tier 1 fixtures."""

from __future__ import annotations

import pytest

from detector.engine import _analyze_in_process
from detector.policy import finalize
from detector.rules.base import CATALOG
from detector.rules.family_b_balance import BAL_PRIV_MINT
from tests.detector.analysis_util import load_tier1_label, make_ctx, run_and_finalize, tier1_ctx
from tests.detector.conftest import tier1_sol

FAMILY_B = (
    "BAL_PRIV_MINT",
    "BAL_PRIV_BURN_OTHER",
    "BAL_DIRECT_SET",
    "BAL_TRANSFER_HIDDEN_MINT",
    "VIEW_CALLER_DEPENDENT",
)

OUR_RULES = frozenset(
    {
        "PRIV_ROLE",
        "EXIT_ADDR_GATE",
        "EXIT_GLOBAL_SWITCH",
        "EXIT_AMOUNT_LIMIT",
        "EXIT_TIME_GATE",
        "EXIT_SELL_ONLY",
        "EXIT_CALLBACK_CYCLE",
        "FEE_UNBOUNDED",
        "BAL_PRIV_MINT",
        "BAL_PRIV_BURN_OTHER",
        "BAL_DIRECT_SET",
        "BAL_TRANSFER_HIDDEN_MINT",
        "VIEW_CALLER_DEPENDENT",
        "OWN_HIDDEN_ROLE",
        "OWN_FAKE_RENOUNCE",
        "OWN_REASSIGN_NONSTD",
        "OWN_TX_ORIGIN",
    }
)


def _mal_severity(rule_id: str, preferred: str) -> str:
    if CATALOG[rule_id][1] == "INFO":
        return "INFO"
    if preferred == "Uncertain":
        return "MED"
    return "HIGH"


def _hits(findings, rule_id: str):
    return [f for f in findings if f.rule_id == rule_id]


@pytest.fixture(scope="module")
def family_b_rules():
    from detector.rules.family_b_balance import RULES

    return RULES


@pytest.mark.parametrize("rule_id", FAMILY_B)
def test_family_b_mal_fires(slither_for, family_b_rules, rule_id: str) -> None:
    label = load_tier1_label(rule_id, "mal")
    ctx = tier1_ctx(slither_for, rule_id, "mal")
    findings = run_and_finalize(ctx, family_b_rules)
    hits = _hits(findings, rule_id)
    assert hits, f"{rule_id}/mal produced no findings"
    want = _mal_severity(rule_id, label["preferred_verdict"])
    assert any(f.severity == want for f in hits), [(f.function, f.severity) for f in hits]
    expected_fns = label.get("expected_functions") or []
    if expected_fns:
        got = {f.function for f in hits}
        assert got & set(expected_fns), f"{got} vs {expected_fns}"


@pytest.mark.parametrize("rule_id", FAMILY_B)
def test_family_b_ben_after_finalize(slither_for, family_b_rules, rule_id: str) -> None:
    label = load_tier1_label(rule_id, "ben")
    ctx = tier1_ctx(slither_for, rule_id, "ben")
    findings = run_and_finalize(ctx, family_b_rules)
    hits = _hits(findings, rule_id)
    accepted = list(label["accepted_verdicts"])
    if accepted == ["Benign"]:
        med_high = [f for f in hits if f.severity in ("HIGH", "MED")]
        assert med_high == [], [(f.function, f.severity, f.discriminators) for f in med_high]
    else:
        assert all(f.severity != "HIGH" for f in hits), [(f.function, f.severity) for f in hits]


@pytest.mark.parametrize("rule_id", FAMILY_B)
def test_family_b_file_verdict(rule_id: str) -> None:
    mal_path = tier1_sol(rule_id, "mal")
    mal_label = load_tier1_label(rule_id, "mal")
    mal = _analyze_in_process(str(mal_path), f"{rule_id}/mal/{mal_path.name}")
    assert mal["verdict"] == mal_label["preferred_verdict"], mal

    ben_path = tier1_sol(rule_id, "ben")
    ben_label = load_tier1_label(rule_id, "ben")
    ben = _analyze_in_process(str(ben_path), f"{rule_id}/ben/{ben_path.name}")
    other_high = [
        f
        for f in ben.get("findings") or []
        if f.get("severity") == "HIGH" and f.get("rule_id") not in OUR_RULES
    ]
    if other_high:
        pytest.xfail(
            f"other-family HIGH on {rule_id}/ben: "
            f"{[(f.get('rule_id'), f.get('function')) for f in other_high]}"
        )
    assert ben["verdict"] in ben_label["accepted_verdicts"], ben


_LOCAL_CAP_SRC = """\
pragma solidity ^0.8.20;
error Over();
contract G {
    uint256 private immutable _cap;
    uint256 private _supply;
    mapping(address => uint256) b;
    address o;
    constructor(uint256 c) { _cap = c; o = msg.sender; }
    function cap() public view returns (uint256) { return _cap; }
    function totalSupply() public view returns (uint256) { return _supply; }
    function mint(address t, uint256 a) external {
        require(msg.sender == o);
        _supply += a;
        b[t] += a;
        uint256 m = cap();
        uint256 s = totalSupply();
        if (s > m) revert Over();
    }
}
"""

_WRITABLE_CAP_SRC = """\
pragma solidity ^0.8.20;
error Over();
contract H {
    uint256 public capVar;
    uint256 private _supply;
    mapping(address => uint256) b;
    address o;
    constructor() { o = msg.sender; }
    function setCap(uint256 c) external { require(msg.sender == o); capVar = c; }
    function totalSupply() public view returns (uint256) { return _supply; }
    function mint(address t, uint256 a) external {
        require(msg.sender == o);
        _supply += a;
        b[t] += a;
        uint256 m = capVar;
        uint256 s = totalSupply();
        if (s > m) revert Over();
    }
}
"""


def test_bal_priv_mint_local_cap_is_info_after_finalize(slither_for, tmp_path) -> None:
    src = tmp_path / "G.sol"
    src.write_text(_LOCAL_CAP_SRC, encoding="utf-8")
    ctx = make_ctx(slither_for, src, "G")
    hits = [f for f in finalize(BAL_PRIV_MINT(ctx)) if f.rule_id == "BAL_PRIV_MINT"]
    assert hits, "BAL_PRIV_MINT produced no findings"
    assert all("constant_cap" in f.discriminators for f in hits), [f.discriminators for f in hits]
    assert all(f.severity == "INFO" for f in hits), [(f.function, f.severity) for f in hits]


def test_bal_priv_mint_writable_cap_stays_high(slither_for, tmp_path) -> None:
    src = tmp_path / "H.sol"
    src.write_text(_WRITABLE_CAP_SRC, encoding="utf-8")
    ctx = make_ctx(slither_for, src, "H")
    hits = [f for f in finalize(BAL_PRIV_MINT(ctx)) if f.rule_id == "BAL_PRIV_MINT"]
    assert hits, "BAL_PRIV_MINT produced no findings"
    assert all("constant_cap" not in f.discriminators for f in hits), [f.discriminators for f in hits]
    assert any(f.severity == "HIGH" for f in hits), [(f.function, f.severity) for f in hits]
