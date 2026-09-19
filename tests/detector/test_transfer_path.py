"""Transfer-path, end nodes, and gate-read predicates."""

from __future__ import annotations

from detector.analysis.transfer_path import SIG_TRANSFER, SIG_TRANSFER_FROM
from tests.detector.analysis_util import fn, svar, tier1_ctx, tier3_ctx


def _shapes(ctx, name: str) -> set[str]:
    return {g.shape for g in ctx.gate_reads if g.var.name == name}


def _key_sources(ctx, name: str) -> set[str | None]:
    return {g.key_source for g in ctx.gate_reads if g.var.name == name}


def test_exit_addr_gate_path_and_map_gate(slither_for) -> None:
    ctx = tier1_ctx(slither_for, "EXIT_ADDR_GATE", "mal")
    root_names = {f.solidity_signature for f in ctx.transfer_roots}
    assert SIG_TRANSFER in root_names
    assert SIG_TRANSFER_FROM in root_names
    path_names = {f.name for f in ctx.transfer_path}
    assert "_transfer" in path_names
    assert "map_addr_bool" in _shapes(ctx, "blacklist")
    keys = _key_sources(ctx, "blacklist")
    assert "from" in keys
    assert "to" in keys


def test_exit_global_switch_bool_gate(slither_for) -> None:
    mal = tier1_ctx(slither_for, "EXIT_GLOBAL_SWITCH", "mal")
    assert "bool" in _shapes(mal, "paused")

    ben = tier1_ctx(slither_for, "EXIT_GLOBAL_SWITCH", "ben")
    assert "bool" in _shapes(ben, "_paused")


def test_exit_amount_and_time_and_sell(slither_for) -> None:
    amount = tier1_ctx(slither_for, "EXIT_AMOUNT_LIMIT", "mal")
    assert "numeric_vs_amount" in _shapes(amount, "maxTx")

    time_mal = tier1_ctx(slither_for, "EXIT_TIME_GATE", "mal")
    assert "numeric_vs_time" in _shapes(time_mal, "tradingStart")

    sell = tier1_ctx(slither_for, "EXIT_SELL_ONLY", "mal")
    assert "address_vs_to" in _shapes(sell, "pair")
    assert any(g.end_node.kind == "if_revert" for g in sell.gate_reads if g.var.name == "pair")

    time_ben = tier1_ctx(slither_for, "EXIT_TIME_GATE", "ben")
    assert time_ben.gate_reads == [] or all(
        g.var.name != "launchTime" for g in time_ben.gate_reads
    )
    assert not any(g.var.is_immutable for g in time_ben.gate_reads)

    sell_ben = tier1_ctx(slither_for, "EXIT_SELL_ONLY", "ben")
    assert not any(g.var.name == "pair" for g in sell_ben.gate_reads)


def test_reflection_guard_conditions(slither_for) -> None:
    ctx = tier3_ctx(slither_for, "reflection_token", "ReflectionToken.sol", "ReflectionToken")
    inner = fn(ctx, "_transfer")
    found = False
    for end in ctx.end_nodes:
        if end.node.function is not inner and end.node.function.name != "_transfer":
            continue
        expr = str(end.node.expression or "")
        content = ""
        if end.node.source_mapping is not None:
            content = end.node.source_mapping.content or ""
        if "maxTxAmount" not in expr and "maxTxAmount" not in content:
            continue
        if end.kind != "require":
            continue
        guards = " ".join(
            (
                (g.source_mapping.content if g.source_mapping is not None else "")
                or " ".join(v.name for v in g.state_variables_read)
                or str(g.expression or "")
            )
            for g in end.guard_conditions
        )
        assert "maxTxUntil" in guards or "block.timestamp" in guards
        found = True
        break
    assert found, [(e.kind, e.node.expression, e.guard_conditions) for e in ctx.end_nodes]


def test_usdc_modifier_args_are_gate_keys(slither_for) -> None:
    ctx = tier3_ctx(slither_for, "usdc_fiattoken", "FiatTokenV1.sol", "FiatTokenV1")
    assert "map_addr_bool" in _shapes(ctx, "_deprecatedBlacklisted")
    keys = _key_sources(ctx, "_deprecatedBlacklisted")
    assert "msg.sender" in keys
    assert "to" in keys
    assert "from" in keys


def test_external_calls_resolve_state_vars(slither_for) -> None:
    ext = tier1_ctx(slither_for, "STRUCT_EXTERNAL_GATE", "mal")
    targets = {v.name for _, _, v in ext.external_calls_on_path if v is not None}
    assert "guard" in targets

    cb = tier1_ctx(slither_for, "EXIT_CALLBACK_CYCLE", "mal")
    targets = {v.name for _, _, v in cb.external_calls_on_path if v is not None}
    assert "hook" in targets
