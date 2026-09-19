"""Catalog constants and Finding constructor. Mirrors baybench/catalog.yaml."""

from __future__ import annotations

from collections.abc import Iterable

from detector.model import Finding

FAMILIES = ("A", "B", "C", "D", "E", "F", "G")

CATALOG: dict[str, tuple[str, str]] = {
    "PRIV_ROLE": ("A", "INFO"),
    "EXIT_ADDR_GATE": ("A", "HIGH"),
    "EXIT_GLOBAL_SWITCH": ("A", "HIGH"),
    "EXIT_AMOUNT_LIMIT": ("A", "HIGH"),
    "EXIT_TIME_GATE": ("A", "MED"),
    "EXIT_SELL_ONLY": ("A", "HIGH"),
    "EXIT_CALLBACK_CYCLE": ("A", "HIGH"),
    "FEE_UNBOUNDED": ("A", "HIGH"),
    "FEE_ADDR_MUTABLE": ("C", "MED"),
    "BAL_PRIV_MINT": ("B", "HIGH"),
    "BAL_PRIV_BURN_OTHER": ("B", "HIGH"),
    "BAL_DIRECT_SET": ("B", "HIGH"),
    "BAL_TRANSFER_HIDDEN_MINT": ("B", "HIGH"),
    "VIEW_CALLER_DEPENDENT": ("B", "HIGH"),
    "LEAK_ARBITRARY_TRANSFERFROM": ("C", "HIGH"),
    "LEAK_EXEMPT_PATH": ("C", "HIGH"),
    "LEAK_PRIV_SWEEP": ("C", "HIGH"),
    "OWN_HIDDEN_ROLE": ("D", "HIGH"),
    "OWN_FAKE_RENOUNCE": ("D", "HIGH"),
    "OWN_REASSIGN_NONSTD": ("D", "HIGH"),
    "OWN_TX_ORIGIN": ("D", "MED"),
    "STRUCT_EXTERNAL_GATE": ("E", "MED"),
    "STRUCT_DELEGATECALL_SETTABLE": ("E", "HIGH"),
    "STRUCT_SELFDESTRUCT": ("E", "HIGH"),
    "STRUCT_PROXY_EOA_ADMIN": ("E", "MED"),
    "DRAIN_APPROVAL_PULL": ("F", "HIGH"),
    "HONEYPOT_LEGACY": ("F", "MED"),
    "PONZI_SHAPE": ("G", "MED"),
    "SLITHER_HIGH_OVERLAY": ("C", "INFO"),
}


def make_finding(
    rule_id: str,
    *,
    contract: str,
    function: str,
    lines: Iterable[int],
    reasoning: str,
    discriminators: tuple[str, ...] = (),
) -> Finding:
    family, base_severity = CATALOG[rule_id]
    return Finding(
        rule_id=rule_id,
        family=family,
        severity=base_severity,
        contract=contract,
        function=function,
        lines=tuple(lines),
        reasoning=reasoning,
        base_severity=base_severity,
        discriminators=tuple(discriminators),
        counts_for_escalation=True,
    )
