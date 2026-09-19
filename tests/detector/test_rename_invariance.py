"""DT-8 analysis half: identifier renaming must not change predicate shapes."""

from __future__ import annotations

from collections import Counter

from detector.analysis import privilege
from detector.compile import compile_file
from tests.detector.analysis_util import make_ctx, tier1_sol
from tests.detector.rename_util import alpha_rename


def _snapshot(ctx) -> tuple:
    privileged = [f for f in ctx.functions if privilege.is_privileged(f)]
    kinds: list[str] = []
    for fn in ctx.functions:
        kinds.extend(a.kind for a in privilege.auth_atoms(fn))
    shapes = [g.shape for g in ctx.gate_reads]
    return (
        len(privileged),
        Counter(kinds),
        Counter(shapes),
        len(ctx.privileged_writable),
        (
            len(ctx.bindings.balance_vars),
            len(ctx.bindings.supply_vars),
            len(ctx.bindings.allowance_vars),
        ),
    )


def _assert_isomorphic(slither_for, tmp_path, rule_id: str) -> None:
    path = tier1_sol(rule_id, "mal")
    original = make_ctx(slither_for, path)
    source = path.read_text(encoding="utf-8")
    renamed = alpha_rename(source, original.slither)
    dest = tmp_path / f"{rule_id}.sol"
    dest.write_text(renamed, encoding="utf-8")
    renamed_slither = compile_file(dest)
    renamed_ctx = make_ctx(lambda p: renamed_slither, dest)
    assert _snapshot(original) == _snapshot(renamed_ctx)


def test_rename_invariance_priv_role(slither_for, tmp_path) -> None:
    _assert_isomorphic(slither_for, tmp_path, "PRIV_ROLE")


def test_rename_invariance_own_hidden_role(slither_for, tmp_path) -> None:
    _assert_isomorphic(slither_for, tmp_path, "OWN_HIDDEN_ROLE")


def test_rename_invariance_own_tx_origin(slither_for, tmp_path) -> None:
    _assert_isomorphic(slither_for, tmp_path, "OWN_TX_ORIGIN")


def test_rename_invariance_exit_addr_gate(slither_for, tmp_path) -> None:
    _assert_isomorphic(slither_for, tmp_path, "EXIT_ADDR_GATE")
