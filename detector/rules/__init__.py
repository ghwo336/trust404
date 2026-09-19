"""Rule registry: load family_* and overlay modules at import time."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable

from detector.analysis.context import ContractContext
from detector.model import Finding

RULES: list[Callable[[ContractContext], list[Finding]]] = []


def _discover() -> list[Callable[[ContractContext], list[Finding]]]:
    import detector.rules as pkg

    names = sorted(
        module.name
        for module in pkgutil.iter_modules(pkg.__path__)
        if module.name.startswith("family_") or module.name == "overlay"
    )
    found: list[Callable[[ContractContext], list[Finding]]] = []
    for name in names:
        loaded = importlib.import_module(f"detector.rules.{name}")
        found.extend(getattr(loaded, "RULES", None) or [])
    return found


RULES = _discover()


def rule_ids_registered() -> list[str]:
    return [fn.__name__ for fn in RULES]
