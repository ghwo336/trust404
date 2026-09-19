"""Shared helpers for detector analysis tests."""

from __future__ import annotations

from pathlib import Path

import yaml

from detector.analysis.context import ContractContext
from detector.engine import target_contracts
from detector.model import Finding
from detector.policy import finalize
from tests.detector.conftest import TIER1, TIER3, tier1_sol


def make_ctx(slither_for, path: Path, name: str | None = None) -> ContractContext:
    slither = slither_for(path)
    contracts = target_contracts(slither, path)
    if name is not None:
        picked = [c for c in contracts if c.name == name]
        assert picked, f"{name} not in {[c.name for c in contracts]}"
        contract = picked[0]
    else:
        assert contracts, path
        contract = contracts[0]
    return ContractContext(slither=slither, contract=contract, input_root=path.parent)


def tier1_ctx(slither_for, rule_id: str, twin: str, name: str | None = None) -> ContractContext:
    return make_ctx(slither_for, tier1_sol(rule_id, twin), name)


def tier3_ctx(slither_for, folder: str, filename: str, name: str) -> ContractContext:
    path = TIER3 / folder / filename
    return make_ctx(slither_for, path, name)


def fn(ctx: ContractContext, name: str, *, sig: str | None = None):
    pool = list(ctx.functions) + list(getattr(ctx.contract, "functions_and_modifiers", []) or [])
    matches = []
    seen: set[int] = set()
    for item in pool:
        if id(item) in seen:
            continue
        seen.add(id(item))
        if item.name != name:
            continue
        if sig is not None and item.solidity_signature != sig:
            continue
        matches.append(item)
    preferred = [item for item in matches if getattr(item, "is_implemented", True) and not getattr(item, "is_shadowed", False)]
    chosen = preferred or matches
    assert chosen, f"{name} {sig} not found"
    return chosen[0]


def svar(ctx: ContractContext, name: str):
    pools: list = []
    contract = ctx.contract
    pools.extend(getattr(contract, "state_variables_ordered", []) or [])
    pools.extend(contract.state_variables)
    for inherited in getattr(contract, "inheritance", []) or []:
        pools.extend(getattr(inherited, "state_variables_ordered", []) or [])
        pools.extend(inherited.state_variables)
    matches = [v for v in pools if v.name == name]
    assert matches, f"state var {name} not found"
    return matches[0]


def load_tier1_label(rule_id: str, twin: str) -> dict:
    path = TIER1 / rule_id / twin / "labels.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_tier3_label(folder: str) -> dict:
    path = TIER3 / folder / "labels.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def run_and_finalize(ctx: ContractContext, rule_fns) -> list[Finding]:
    raw: list[Finding] = []
    for rule in rule_fns:
        raw.extend(rule(ctx))
    adjusted, _shape = finalize(raw)
    return list(adjusted)
