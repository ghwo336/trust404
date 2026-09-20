"""Balance binding, write classification, and arith_kind."""

from __future__ import annotations

from slither.slithir.operations import InternalCall, LibraryCall

from detector.analysis._ir import is_if_node
from detector.analysis.balances import arith_kind, balance_writes, is_constant_bound
from tests.detector.analysis_util import fn, make_ctx, svar, tier1_ctx, tier3_ctx


def test_bind_priv_mint(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "BAL_PRIV_MINT", "mal")
    assert ctx.bindings.balance_vars == (svar(ctx, "_balances"),)
    assert ctx.bindings.supply_vars == (svar(ctx, "_totalSupply"),)


def test_bind_bancor_public_getter(slither_for) -> None:
    ctx = tier3_ctx(slither_for, "bancor_smarttoken", "SmartToken.sol", "SmartToken")
    assert ctx.bindings.balance_vars == (svar(ctx, "balanceOf"),)
    assert svar(ctx, "totalSupply") in ctx.bindings.supply_vars


def test_bind_priv_role_public_mapping(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "PRIV_ROLE", "mal")
    assert ctx.bindings.balance_vars == (svar(ctx, "balanceOf"),)


def test_bind_allowance(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_ARBITRARY_TRANSFERFROM", "ben")
    assert ctx.bindings.allowance_vars == (svar(ctx, "allowance"),)


def test_balance_writes_mint_burn_set(slither_for) -> None:
    mint_ctx = tier1_ctx(slither_for, "BAL_PRIV_MINT", "mal")
    mint_writes = [
        w
        for w in balance_writes(fn(mint_ctx, "mint"), mint_ctx.bindings)
        if w.var.name == "_balances"
    ]
    assert len(mint_writes) == 1
    assert mint_writes[0].kind == "credit"
    assert mint_writes[0].key_source == "param"

    burn_ctx = tier1_ctx(slither_for, "BAL_PRIV_BURN_OTHER", "mal")
    burn_writes = [
        w
        for w in balance_writes(fn(burn_ctx, "burnFrom"), burn_ctx.bindings)
        if w.var.name == "_balances"
    ]
    assert len(burn_writes) == 1
    assert burn_writes[0].kind == "debit"
    assert burn_writes[0].key_source == "param"

    set_ctx = tier1_ctx(slither_for, "BAL_DIRECT_SET", "mal")
    set_writes = balance_writes(fn(set_ctx, "setBalance"), set_ctx.bindings)
    assert len(set_writes) == 1
    assert set_writes[0].kind == "set"
    assert set_writes[0].key_source == "param"
    assert set_writes[0].value_reads_same_key is False


def test_hidden_mint_raw_amount(slither_for) -> None:
    mal = tier1_ctx(slither_for, "BAL_TRANSFER_HIDDEN_MINT", "mal")
    inner = fn(mal, "_transfer")
    roles = {p: role for p, role in zip(inner.parameters, ("from", "to", "amount"))}
    writes = [w for w in balance_writes(inner, mal.bindings, param_roles=roles) if w.kind == "credit"]
    sources = {w.key_source for w in writes}
    assert "to" in sources
    assert "state" in sources
    assert all(w.value_is_raw_amount for w in writes)

    ben = tier1_ctx(slither_for, "BAL_TRANSFER_HIDDEN_MINT", "ben")
    inner_b = fn(ben, "_transfer")
    roles_b = {p: role for p, role in zip(inner_b.parameters, ("from", "to", "amount"))}
    credits = [w for w in balance_writes(inner_b, ben.bindings, param_roles=roles_b) if w.kind == "credit"]
    to_credit = [w for w in credits if w.key_source == "to"]
    state_credit = [w for w in credits if w.key_source == "state"]
    assert to_credit and to_credit[0].value_is_raw_amount is False
    assert state_credit and state_credit[0].value_is_raw_amount is False


def test_arith_kind_bancor(slither_for) -> None:
    ctx = tier3_ctx(slither_for, "bancor_smarttoken", "SmartToken.sol", "SmartToken")
    issue = fn(ctx, "issue")
    add_call = None
    sub_fn = fn(ctx, "safeSub")
    add_fn = fn(ctx, "safeAdd")
    for node in issue.nodes:
        for ir in node.irs:
            if isinstance(ir, (InternalCall, LibraryCall)) and ir.function is add_fn:
                add_call = ir
    assert add_call is not None
    assert arith_kind(add_call) == "add"
    destroy = fn(ctx, "destroy")
    sub_call = None
    for node in destroy.nodes:
        for ir in node.irs:
            if isinstance(ir, (InternalCall, LibraryCall)) and ir.function is sub_fn:
                sub_call = ir
                break
        if sub_call is not None:
            break
    assert sub_call is not None
    assert arith_kind(sub_call) == "sub"


def test_constant_bound(slither_for) -> None:
    cap = tier1_ctx(slither_for, "BAL_PRIV_MINT", "ben")
    mint = fn(cap, "mint")
    cap_node = next(n for n in mint.nodes if n.contains_require_or_assert() and "CAP" in str(n.expression))
    assert is_constant_bound(cap_node, cap) is True

    floor = tier1_ctx(slither_for, "EXIT_AMOUNT_LIMIT", "ben")
    setter = fn(floor, "setMaxTx")
    floor_node = next(
        n for n in setter.nodes if n.contains_require_or_assert() and "totalSupply" in str(n.expression)
    )
    assert is_constant_bound(floor_node, floor) is True

    mal = tier1_ctx(slither_for, "EXIT_AMOUNT_LIMIT", "mal")
    inner = fn(mal, "_transfer")
    gate = next(n for n in inner.nodes if n.contains_require_or_assert() and "maxTx" in str(n.expression))
    assert is_constant_bound(gate, mal) is False


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


def _mint_if_node(ctx):
    mint = fn(ctx, "mint")
    return next(node for node in mint.nodes if is_if_node(node))


def test_constant_bound_through_same_function_locals(slither_for, tmp_path) -> None:
    src = tmp_path / "G.sol"
    src.write_text(_LOCAL_CAP_SRC, encoding="utf-8")
    ctx = make_ctx(slither_for, src, "G")
    assert is_constant_bound(_mint_if_node(ctx), ctx) is True


def test_constant_bound_rejects_privileged_writable_through_local(slither_for, tmp_path) -> None:
    src = tmp_path / "H.sol"
    src.write_text(_WRITABLE_CAP_SRC, encoding="utf-8")
    ctx = make_ctx(slither_for, src, "H")
    assert is_constant_bound(_mint_if_node(ctx), ctx) is False
