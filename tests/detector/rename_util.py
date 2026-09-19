"""Alpha-rename user identifiers in Solidity sources (DT-8 analysis half)."""

from __future__ import annotations

import re

from slither.core.declarations.event import Event

PROTECTED = frozenset(
    {
        "transfer",
        "transferFrom",
        "approve",
        "balanceOf",
        "totalSupply",
        "allowance",
        "constructor",
        "receive",
        "fallback",
        "permit",
    }
)


def _collect_identifiers(slither) -> list[str]:
    names: set[str] = set()
    for contract in slither.contracts:
        if contract.name:
            names.add(contract.name)
        for event in getattr(contract, "events", []) or []:
            if isinstance(event, Event) and event.name:
                names.add(event.name)
            elif getattr(event, "name", None):
                names.add(event.name)
        for var in contract.state_variables:
            if var.name:
                names.add(var.name)
        for fn in contract.functions_and_modifiers:
            if fn.name:
                names.add(fn.name)
            for param in fn.parameters:
                if param.name:
                    names.add(param.name)
            for local in fn.local_variables:
                if local.name:
                    names.add(local.name)
            for ret in fn.returns:
                if ret.name:
                    names.add(ret.name)
    names.discard("")
    names -= PROTECTED
    return sorted(names, key=lambda name: (-len(name), name))


def alpha_rename(source: str, slither) -> str:
    """Rename every user-defined identifier in `source` using `slither` declarations."""
    names = _collect_identifiers(slither)
    used = set(names) | set(PROTECTED)
    fresh: list[str] = []
    idx = 1
    while len(fresh) < len(names):
        cand = f"x_{idx}"
        idx += 1
        if cand in used:
            continue
        used.add(cand)
        fresh.append(cand)
    rewritten = source
    for old, new in zip(names, fresh):
        rewritten = re.sub(rf"\b{re.escape(old)}\b", new, rewritten)
    return rewritten
