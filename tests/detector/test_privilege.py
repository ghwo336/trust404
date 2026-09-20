"""Privilege predicates on Tier 1 fixtures."""

from __future__ import annotations

from pathlib import Path

from detector.analysis import privilege
from detector.analysis.context import ContractContext
from detector.compile import compile_file_ex
from detector.engine import target_contracts
from tests.detector.analysis_util import fn, make_ctx, svar, tier1_ctx, tier3_ctx
from tests.detector.conftest import CASES, HARNESS


def _ctx_ex(path: Path, name: str | None = None) -> ContractContext:
    compiled = compile_file_ex(path, input_root=path.parent)
    contracts = target_contracts(compiled.slither, compiled.source_path)
    if name is not None:
        picked = [c for c in contracts if c.name == name]
        assert picked, f"{name} not in {[c.name for c in contracts]}"
        contract = picked[0]
    else:
        assert contracts, path
        contract = contracts[0]
    return ContractContext(slither=compiled.slither, contract=contract, input_root=path.parent)


def test_exit_addr_gate_mal(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "EXIT_ADDR_GATE", "mal")
    set_bots = fn(ctx, "setBots")
    transfer = fn(ctx, "transfer")
    inner = fn(ctx, "_transfer")
    assert privilege.is_privileged(set_bots)
    atoms = privilege.auth_atoms(set_bots)
    assert any(a.kind == "eq_state_address" and a.auth_var.name == "owner" for a in atoms)
    assert not privilege.is_privileged(transfer)
    assert not privilege.is_privileged(inner)
    pw_names = {v.name for v in ctx.privileged_writable}
    assert "blacklist" in pw_names
    assert "owner" not in pw_names


def test_priv_role_mal_map_bool(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "PRIV_ROLE", "mal")
    setter = fn(ctx, "setBlacklist")
    assert privilege.is_privileged(setter)
    atoms = privilege.auth_atoms(setter)
    assert any(a.kind == "map_bool" and a.auth_var.name == "_admins" for a in atoms)


def test_deny_list_is_not_auth_atom(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "PRIV_ROLE", "mal")
    transfer = fn(ctx, "transfer")
    assert not privilege.is_privileged(transfer)
    pw_names = {v.name for v in ctx.privileged_writable}
    assert "balanceOf" not in pw_names
    assert "blacklist" in pw_names
    assert privilege.is_privileged(fn(ctx, "setBlacklist"))


def test_usdc_privilege_polarity(slither_for) -> None:
    ctx = tier3_ctx(slither_for, "usdc_fiattoken", "FiatTokenV1.sol", "FiatTokenV1")
    for name in ("transfer", "transferFrom", "approve"):
        assert not privilege.is_privileged(fn(ctx, name)), name
    for name in ("mint", "blacklist", "pause", "configureMinter"):
        assert privilege.is_privileged(fn(ctx, name)), name
    auth_names = {v.name for v in ctx.auth_vars}
    assert auth_names == {"_owner", "pauser", "blacklister", "masterMinter", "minters"}
    assert "_deprecatedBlacklisted" not in auth_names


def test_own_tx_origin_mal(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "OWN_TX_ORIGIN", "mal")
    setter = fn(ctx, "setBlacklist")
    assert privilege.is_privileged(setter)
    atoms = privilege.auth_atoms(setter)
    assert any(a.sender_source == "tx.origin" and a.kind == "tx_origin" for a in atoms)


def test_own_hidden_role_exposure(slither_for) -> None:
    mal = tier1_ctx(slither_for, "OWN_HIDDEN_ROLE", "mal")
    assert privilege.is_exposed(mal.contract, svar(mal, "_dev")) is False
    assert privilege.is_exposed(mal.contract, svar(mal, "owner")) is True

    ben = tier1_ctx(slither_for, "OWN_HIDDEN_ROLE", "ben")
    setter = fn(ben, "setBlacklist")
    assert privilege.is_privileged(setter)
    assert privilege.is_exposed(ben.contract, svar(ben, "_owner")) is True


def test_leak_exempt_path_branch_atoms(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_EXEMPT_PATH", "mal")
    inner = fn(ctx, "_transfer")
    branches = privilege.branch_atoms(inner)
    assert any(atom.kind == "map_bool" and atom.auth_var.name == "exempt" for atom, _ in branches)
    branch_writes = [pw for pw in privilege.privileged_writes(ctx.contract) if pw.mode == "branch"]
    assert any(pw.var.name == "_balances" for pw in branch_writes)


def test_allowance_compare_is_not_atom(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "LEAK_ARBITRARY_TRANSFERFROM", "ben")
    tf = fn(ctx, "transferFrom")
    assert not privilege.is_privileged(tf)
    assert privilege.auth_atoms(tf) == []


def test_unprivileged_writers_follow_internal_callees(slither_for) -> None:
    oz = tier3_ctx(
        slither_for, "oz_erc20capped_accesscontrol", "OzErc20CappedAccessControl.sol", "OzErc20CappedAccessControl"
    )
    pw_names = {v.name for v in oz.privileged_writable}
    assert "_balances" not in pw_names

    leak = tier1_ctx(slither_for, "LEAK_EXEMPT_PATH", "mal")
    assert {v.name for v in leak.privileged_writable} == {"exempt"}

    paused = tier1_ctx(slither_for, "EXIT_GLOBAL_SWITCH", "ben")
    assert "_paused" in {v.name for v in paused.privileged_writable}


def test_eq_self_timelock(slither_for) -> None:
    ctx = make_ctx(slither_for, HARNESS / "timelock_self_call" / "MiniTimelock.sol")
    setter = fn(ctx, "setPendingAdmin")
    assert privilege.is_privileged(setter)
    atoms = privilege.auth_atoms(setter)
    assert any(a.kind == "eq_self" and a.sender_source == "msg.sender" for a in atoms)
    kinds = {a.kind for a in atoms}
    assert "eq_self" in kinds


def test_or_operands_do_not_privilege_transfer(slither_for) -> None:
    path = (
        CASES
        / "tier2_realworld"
        / "crpwarner"
        / "0xD217Dc0cAB1C952a7cE6f4D7ca4549CdE1F37bb0_sol"
        / "0xD217Dc0cAB1C952a7cE6f4D7ca4549CdE1F37bb0_sol.sol"
    )
    ctx = make_ctx(slither_for, path, "BaseToken")
    transfer = fn(ctx, "transfer", sig="transfer(address,uint256)")
    assert privilege.is_privileged(transfer) is False


def test_sell_only_pair_compare_is_not_atom(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "EXIT_SELL_ONLY", "mal")
    inner = fn(ctx, "_transfer")
    kinds = {a.kind for a in privilege.auth_atoms(inner)}
    assert "eq_state_address" not in kinds
    assert privilege.auth_atoms(inner) == []


def test_oz_v5_unbounded_mint_is_privileged() -> None:
    path = HARNESS / "oz_v5_unbounded_mint" / "OzV5UnboundedMint.sol"
    ctx = _ctx_ex(path, "OzV5UnboundedMint")
    mint = fn(ctx, "mint")
    assert privilege.is_privileged(mint)
    atoms = privilege.auth_atoms(mint)
    assert any(a.kind == "eq_state_address" and a.sender_source == "msg.sender" for a in atoms)


def test_custom_error_revert_is_privileged(tmp_path: Path) -> None:
    src = tmp_path / "G.sol"
    src.write_text(
        "pragma solidity ^0.8.20;\n"
        "error NotOwner();\n"
        "contract G {\n"
        "    address private o;\n"
        "    constructor(){o=msg.sender;}\n"
        "    mapping(address=>uint256) public b;\n"
        "    function mint(address t,uint256 a) external {\n"
        "        if (msg.sender != o) revert NotOwner();\n"
        "        b[t]+=a;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    mint = fn(_ctx_ex(src, "G"), "mint")
    assert privilege.is_privileged(mint) is True


def test_require_sender_eq_still_privileged(tmp_path: Path) -> None:
    src = tmp_path / "R.sol"
    src.write_text(
        "pragma solidity ^0.8.20;\n"
        "contract R {\n"
        "    address private o;\n"
        "    constructor(){o=msg.sender;}\n"
        "    mapping(address=>uint256) public b;\n"
        "    function mint(address t,uint256 a) external {\n"
        "        require(msg.sender == o);\n"
        "        b[t]+=a;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    mint = fn(_ctx_ex(src, "R"), "mint")
    assert privilege.is_privileged(mint) is True


def test_if_without_revert_is_not_privileged(tmp_path: Path) -> None:
    src = tmp_path / "N.sol"
    src.write_text(
        "pragma solidity ^0.8.20;\n"
        "contract N {\n"
        "    address private o;\n"
        "    constructor(){o=msg.sender;}\n"
        "    mapping(address=>uint256) public b;\n"
        "    function mint(address t,uint256 a) external {\n"
        "        if (msg.sender != o) { b[t] = 0; }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    mint = fn(_ctx_ex(src, "N"), "mint")
    assert privilege.is_privileged(mint) is False
