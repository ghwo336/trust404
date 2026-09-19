"""Slither built-in High-impact detectors, attributed as INFO overlay findings."""

from __future__ import annotations

import inspect
import logging
from typing import Any

from slither.detectors import all_detectors
from slither.detectors.abstract_detector import DetectorClassification

from detector.analysis._ir import source_file
from detector.analysis.context import ContractContext
from detector.model import Finding
from detector.rules.base import make_finding

logger = logging.getLogger("detector.rules.overlay")

_MEMO = "_t404_slither_high_overlay"


def _high_detector_classes() -> list[type]:
    found: list[type] = []
    for _name, obj in inspect.getmembers(all_detectors):
        if inspect.isclass(obj) and getattr(obj, "IMPACT", None) == DetectorClassification.HIGH:
            found.append(obj)
    return found


def _run_cached(slither: Any) -> list:
    cached = getattr(slither, _MEMO, None)
    if cached is not None:
        return cached
    raw: list = []
    try:
        for cls in _high_detector_classes():
            slither.register_detector(cls)
        raw = slither.run_detectors() or []
    except Exception:
        logger.warning("SLITHER_HIGH_OVERLAY failed", exc_info=True)
        raw = []
    try:
        setattr(slither, _MEMO, raw)
    except Exception:
        pass
    return raw


def _target_names(ctx: ContractContext) -> set[str]:
    names = {ctx.contract.name}
    here = source_file(ctx.contract)
    for base in getattr(ctx.contract, "inheritance", []) or []:
        if source_file(base) == here:
            names.add(base.name)
    return names


def _element_contract(element: dict) -> str | None:
    kind = element.get("type")
    if kind == "contract":
        return element.get("name")
    parent = (element.get("type_specific_fields") or {}).get("parent") or {}
    if parent.get("type") == "contract":
        return parent.get("name")
    return parent.get("name")


def _targets_hit(elements: list, names: set[str]) -> bool:
    for element in elements:
        if not isinstance(element, dict):
            continue
        kind = element.get("type")
        if kind == "function" and _element_contract(element) in names:
            return True
        if kind == "contract" and element.get("name") in names:
            return True
    return False


def _first_function_element(elements: list, names: set[str]) -> dict | None:
    for element in elements:
        if not isinstance(element, dict):
            continue
        if element.get("type") != "function":
            continue
        if _element_contract(element) in names:
            return element
    for element in elements:
        if isinstance(element, dict) and element.get("type") == "function":
            return element
    return None


def slither_high_overlay(ctx: ContractContext) -> list[Finding]:
    try:
        raw = _run_cached(ctx.slither)
        names = _target_names(ctx)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for group in raw or []:
            for item in group or []:
                if not isinstance(item, dict):
                    continue
                if str(item.get("impact") or "").lower() != "high":
                    continue
                elements = item.get("elements") or []
                if not _targets_hit(elements, names):
                    continue
                fn_el = _first_function_element(elements, names)
                fn_name = str(fn_el.get("name") or "") if fn_el else ""
                mapping = (fn_el or {}).get("source_mapping") or {}
                lines = tuple(int(n) for n in (mapping.get("lines") or ()))
                check = str(item.get("check") or "")
                desc = str(item.get("description") or "").strip().splitlines()
                first = desc[0] if desc else ""
                key = (check, fn_name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    make_finding(
                        "SLITHER_HIGH_OVERLAY",
                        contract=ctx.contract.name,
                        function=fn_name,
                        lines=lines,
                        reasoning=f"{check}: {first}",
                    )
                )
        return findings
    except Exception:
        logger.warning("SLITHER_HIGH_OVERLAY failed", exc_info=True)
        return []


RULES = [slither_high_overlay]
