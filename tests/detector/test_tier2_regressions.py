"""Tier 2 (real-world) regressions from the Phase 4d iterate loop.

Each test pins one analysis/rule fix to the smallest Tier 2 file that exposed the gap.
Fixtures are referenced in place under cases/tier2_realworld/<dataset>/<id>/<id>.sol.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detector.analysis._ir import guards_of_node, pot_dependent, root_state, values_feeding_condition
from detector.analysis.flows import state_target_calls, value_sends
from detector.analysis.privilege import (
    auth_atoms,
    auth_vars,
    bait_writer_exists,
    depositor_locked,
    is_privileged,
    shadowed_auth_vars,
)
from detector.rules.family_b_balance import RULES as B_RULES
from detector.rules.family_fg import honeypot_legacy
from tests.detector.analysis_util import fn, make_ctx, run_and_finalize, svar, tier1_ctx
from tests.detector.conftest import CASES

TIER2 = CASES / "tier2_realworld"

HB = "honeybadger"
PP = "pied-piper"

# (dataset, case id) → smallest Tier 2 file per fixed shape.
LOTTERY = (HB, "balance_disorder_0x0bf0f154b176c5d90f24e506f10f7f583eb5334d_sol")
X2 = (HB, "balance_disorder_0xe0527863df8abcb3caca7da329eb9c747822aa98_sol")
SELF_ASSIGN = (HB, "balance_disorder_0x5bb52e85c21ca3df3c71da6d03be19cff89e7cf9_sol")
GIFT = (HB, "hidden_state_update_0x7ffc2bd9431b059c509b45b33e77852d47de827d_sol")
COMPANY_WALLET = (HB, "inheritance_disorder_0x787080326e1f7e0eae490efdb18e90cfd0ae2692_sol")
ETH_VAULT = (HB, "inheritance_disorder_0xcacf9396a56e9ff1e3f6533be83a043c36ce0436_sol")
HOMOGLYPH = (HB, "inheritance_disorder_0xf5615138a7f2605e382375fa33ab368661e017ff_sol")
ROUTER = (HB, "straw_man_contract_0x7a7d08bcb2faf27414e86ecf9a0351d928054b6b_sol")
FREE_ETH = (HB, "hidden_transfer_0xdb1c55f6926e7d847ddf8678905ad871a68199d2_sol")
WHILE_TRUE = (HB, "type_deduction_overflow_0x791d0463b8813b827807a36852e4778be01b704e_sol")
MIXER = (HB, "uninitialised_struct_0x783cf9c6754bf826f1727620b4baa19714fedf8d_sol")
ANONIM = (HB, "uninitialised_struct_0xad1aa68300588aa5842751ddcab2afd4a69e9016_sol")
LUCKY = (HB, "uninitialised_struct_0x3268ecb4fcba1ca9f43da8ed05ffc80382cef1da_sol")
FIFTY = (HB, "uninitialised_struct_0x29d6cf436c893c7e44ea926411d5fd4dd763d9b3_sol")
PRESALE = (HB, "skip_empty_string_literal_0xa395480a4a90c7066c8ddb5db83e2718e750641c_sol")
SIMPLE_BET = (HB, "hidden_state_update_0x11f4306f9812b80e75c1411c1cf296b04917b2f0_sol")
QUIZ_RESET = (HB, "hidden_state_update_0x0e8f2803fa16492b948bc470c69e99460942db2b_sol")
DESTROY_6 = (PP, "injected_DestroyToken_6_sol")
RAFFLE = (PP, "injected_DestroyToken_38_sol")
MKR = (PP, "real_0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2_sol")
CW = "crpwarner"
ROLE_SET = (CW, "0xD217Dc0cAB1C952a7cE6f4D7ca4549CdE1F37bb0_sol")


def _tier2_sol(dataset: str, case_id: str) -> Path:
    folder = TIER2 / dataset / case_id
    files = sorted(p for p in folder.glob("*.sol") if "__relaxed__" not in p.name)
    assert len(files) == 1, f"expected one .sol in {folder}, got {files}"
    return files[0]


def _ctx(slither_for, case: tuple[str, str], name: str | None = None):
    return make_ctx(slither_for, _tier2_sol(*case), name)


def _honeypot_reasons(ctx) -> dict[str, str]:
    return {f.function: f.reasoning for f in honeypot_legacy(ctx)}


def _assert_honeypot(ctx, function: str, phrase: str) -> None:
    reasons = _honeypot_reasons(ctx)
    assert function in reasons, reasons
    assert phrase in reasons[function], reasons[function]
    assert all(f.severity == "MED" for f in honeypot_legacy(ctx))


# --- analysis layer -----------------------------------------------------------------


def test_root_state_terminates_on_self_assignment(slither_for) -> None:
    """`manager = manager` (param shadows state) makes the non-SSA def chain cyclic."""
    ctx = _ctx(slither_for, SELF_ASSIGN, "CreditDepositBank")
    function = fn(ctx, "setManager")
    for node in function.nodes:
        for ir in node.irs:
            for var in [getattr(ir, "lvalue", None), *list(getattr(ir, "read", []) or [])]:
                root_state(var, function)  # must not raise RecursionError


def test_condition_values_trace_through_hash_call(slither_for) -> None:
    """`keccak256(number) == secretNumberHash`: the hashed parameter feeds the compare."""
    ctx = _ctx(slither_for, LOTTERY, "Lottery")
    function = fn(ctx, "guess")
    params = set(function.parameters)
    gate = next(node for node in function.nodes if node.contains_if())
    assert params & set(values_feeding_condition(gate)), [str(v) for v in values_feeding_condition(gate)]


def test_silent_if_is_a_gate_and_sum_with_pot_is_pot_dependent(slither_for) -> None:
    """A non-reverting `if` around the send is a gate; `this.balance + msg.value` is pot-dependent."""
    ctx = _ctx(slither_for, LOTTERY, "Lottery")
    function = fn(ctx, "guess")
    sends = value_sends(function)
    assert sends
    node, _to, value, _kind = sends[0]
    assert pot_dependent(value, function)
    gates = guards_of_node(node, function)
    assert gates and all(g.contains_if() for g in gates)


def test_depositor_locked_and_bait_writer_on_gift_receiver(slither_for) -> None:
    """`Put` is payable and writes `receiver` only inside a state-gated silent arm."""
    ctx = _ctx(slither_for, GIFT, "GIFT3600")
    receiver = svar(ctx, "receiver")
    assert depositor_locked(ctx.contract, receiver)
    assert bait_writer_exists(ctx.contract, receiver)


def test_silent_modifier_placeholder_is_an_auth_gate(slither_for) -> None:
    """`modifier onlyOwner { if (msg.sender == Owner) _; }` privileges its users."""
    ctx = _ctx(slither_for, ETH_VAULT, "ETHVault")
    assert is_privileged(fn(ctx, "withdraw"))
    assert is_privileged(fn(ctx, "kill"))
    assert not is_privileged(fn(ctx, "deposit"))


def test_bool_helper_with_return_true_branch_yields_atom(slither_for) -> None:
    """`isOwner()` returning `true` only under `Owner == msg.sender` marks the base var as auth."""
    ctx = _ctx(slither_for, COMPANY_WALLET, "MyCompanyWallet")
    names = {v.name for v in auth_vars(ctx.contract)}
    assert "Owner" in names
    pairs = shadowed_auth_vars(ctx.contract)
    assert pairs, "derived Owner must shadow the base auth var"
    auth, shadow = pairs[0]
    assert auth.name == shadow.name and auth is not shadow


def test_sender_taint_through_internal_auth_helper(slither_for) -> None:
    """DSAuth: `require(isAuthorized(msg.sender, msg.sig))` with `src == owner` in the callee."""
    ctx = _ctx(slither_for, MKR, "DSToken")
    assert is_privileged(fn(ctx, "mint", sig="mint(address,uint256)"))
    assert not is_privileged(fn(ctx, "transfer", sig="transfer(address,uint256)"))


def test_set_membership_library_call_is_a_map_bool_atom(slither_for) -> None:
    """OZ 3.x AccessControl: `hasRole` returns `_roles[role].members.contains(account)` — a
    view library call over a state-rooted set with the sender as the probed element."""
    ctx = _ctx(slither_for, ROLE_SET, "BaseToken")
    mint = fn(ctx, "mint", sig="mint(address,uint256)")
    assert is_privileged(mint)
    assert {a.kind for a in auth_atoms(mint)} == {"map_bool"}
    assert not is_privileged(fn(ctx, "approve", sig="approve(address,uint256)"))
    findings = run_and_finalize(ctx, B_RULES)
    assert any(f.rule_id == "BAL_PRIV_MINT" and f.function == "mint" for f in findings), findings


def test_state_target_calls_include_delegatecall(slither_for) -> None:
    ctx = _ctx(slither_for, ROUTER, "Router")
    calls = state_target_calls(fn(ctx, "transfer"))
    assert [dest.name for _node, _call, dest in calls] == ["DataBase"]


def test_paired_ledger_fallback_binds_disconnected_ledger(slither_for) -> None:
    """No ERC-20 ABI: `m[k] -= x; supply -= x` binds (balances, supply) so BAL_* can see it."""
    ctx = _ctx(slither_for, DESTROY_6, "IntegerOverflowMappingSym1")
    assert [v.name for v in ctx.bindings.balance_vars] == ["balance_test"]
    assert [v.name for v in ctx.bindings.supply_vars] == ["totalSupply"]
    findings = run_and_finalize(ctx, B_RULES)
    hits = [f for f in findings if f.rule_id == "BAL_PRIV_BURN_OTHER"]
    assert hits and hits[0].severity == "HIGH" and hits[0].function == "destroy"


def test_paired_ledger_fallback_stays_silent_on_plain_eth_vault(slither_for) -> None:
    """A deposits mapping with no matching scalar move is not a ledger."""
    ctx = tier1_ctx(slither_for, "HONEYPOT_LEGACY", "ben")
    assert not ctx.bindings.balance_vars
    assert not ctx.bindings.supply_vars


# --- HONEYPOT_LEGACY sub-checks -----------------------------------------------------


@pytest.mark.parametrize(
    ("case", "contract", "function", "phrase"),
    [
        (LOTTERY, "Lottery", "guess", "caller-supplied compare"),
        (X2, "X2", "multiplicate", "msg.value against the contract balance"),
        (GIFT, "GIFT3600", "Get", "caller-supplied compare"),
        (COMPANY_WALLET, "MyCompanyWallet", "setup", "shadows the Ownable auth var"),
        # `owner['Stephen'] == msg.sender` gates the pot; the payable writer fills `owner['Stephеn']`
        (HOMOGLYPH, "BankOfStephen", "withdraw", "caller-supplied compare"),
        (ROUTER, "Router", "transfer", "straw man"),
        (FREE_ETH, "FreeEth", "GetFreebie", "second send is empty"),
        (WHILE_TRUE, "Test1", "Test", "narrow deduced counter"),
        (MIXER, "ETH_MIXER", "MakeTransfer", "uninitialised storage pointer"),
        (ANONIM, "ETH_ANONIM_TRANSFER", "MakeTransfer", "uninitialised storage pointer"),
        # the exit is `selfdestruct(msg.sender)`: the quirk does not care about the send kind
        (FIFTY, "Lottery50chance", "play", "uninitialised storage pointer"),
        (LUCKY, "AddressLottery", "participate", "constructor-set secret"),
        (PRESALE, "PreSaleFund", "Divest", "empty string literal"),
        (SIMPLE_BET, "SimpleBet", "bet", "bool switch"),
        (QUIZ_RESET, "QuizGameTest1", "Play", "caller-supplied compare"),
    ],
)
def test_honeypot_legacy_fires_on_tier2_shape(slither_for, case, contract, function, phrase) -> None:
    ctx = _ctx(slither_for, case, contract)
    _assert_honeypot(ctx, function, phrase)


def test_locked_switch_ignores_pausable_refund(slither_for) -> None:
    """`if (paused) { msg.sender.transfer(msg.value); return; }` refunds the caller's own deposit."""
    ctx = _ctx(slither_for, RAFFLE, "Ethraffle_v4b")
    reasons = _honeypot_reasons(ctx)
    assert "buyTickets" not in reasons, reasons
    assert not any("bool switch" in why for why in reasons.values()), reasons


def test_honeypot_legacy_double_pot_beats_nested_privilege(slither_for) -> None:
    """The whole-pot double send fires even though `withdraw` in the same file is privileged."""
    ctx = _ctx(slither_for, FREE_ETH, "FreeEth")
    reasons = _honeypot_reasons(ctx)
    assert set(reasons) == {"GetFreebie"}, reasons
