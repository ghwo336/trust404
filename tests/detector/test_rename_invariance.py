"""DT-8 analysis half: identifier renaming must not change predicate shapes."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from detector.analysis import privilege
from detector.compile import compile_file
from detector.engine import _analyze_in_process
from tests.detector.analysis_util import make_ctx, tier1_sol
from tests.detector.conftest import REPO_ROOT
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


def _rule_multiset(path: Path, rel: str) -> Counter:
    payload = _analyze_in_process(str(path), rel)
    return Counter((item["rule_id"], item["severity"]) for item in payload.get("findings") or [])


@pytest.mark.parametrize(
    "rule_id",
    ("PRIV_ROLE", "OWN_HIDDEN_ROLE", "OWN_TX_ORIGIN", "EXIT_ADDR_GATE"),
)
def test_rename_invariance_rule_multiset(slither_for, tmp_path, rule_id: str) -> None:
    path = tier1_sol(rule_id, "mal")
    original = make_ctx(slither_for, path)
    source = path.read_text(encoding="utf-8")
    renamed = alpha_rename(source, original.slither)
    dest = tmp_path / f"{rule_id}.sol"
    dest.write_text(renamed, encoding="utf-8")
    left = _rule_multiset(path, f"{rule_id}/mal/{path.name}")
    right = _rule_multiset(dest, dest.name)
    assert left == right


_IDENT_WORD_RE = re.compile(
    r"['\"](owner|admin|blacklist|whitelist|bot|pause|paused|fee|tax|dev|"
    r"marketing|treasury|maxTx|trading|_owner|onlyOwner)['\"]"
)


def test_no_quoted_identifier_wordlists() -> None:
    roots = [
        REPO_ROOT / "detector" / "rules",
        REPO_ROOT / "detector" / "analysis",
    ]
    hits: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                if _IDENT_WORD_RE.search(line):
                    hits.append(f"{path.relative_to(REPO_ROOT)}:{lineno}:{line.strip()}")
    assert hits == []
