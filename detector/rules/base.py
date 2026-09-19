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


def node_lines(node) -> tuple[int, ...]:
    mapping = getattr(node, "source_mapping", None)
    lines = getattr(mapping, "lines", None) if mapping is not None else None
    if lines:
        return tuple(int(item) for item in lines)
    function = getattr(node, "function", None)
    fn_map = getattr(function, "source_mapping", None) if function is not None else None
    fn_lines = getattr(fn_map, "lines", None) if fn_map is not None else None
    if fn_lines:
        return tuple(int(item) for item in fn_lines)
    return ()


def function_name(function) -> str:
    return getattr(function, "name", None) or ""


def contract_name(contract) -> str:
    return getattr(contract, "name", None) or ""


def shape_discriminators(ctx, function) -> tuple[str, ...]:
    from detector.analysis import roles
    from detector.analysis.privilege import auth_atoms

    discs: list[str] = []
    atoms = auth_atoms(function)
    auth = []
    seen: set[int] = set()
    for atom in atoms:
        if id(atom.auth_var) in seen:
            continue
        seen.add(id(atom.auth_var))
        auth.append(atom.auth_var)
    if auth and all(roles.managed_role(ctx, var) for var in auth):
        discs.append("managed_role")
    if roles.library_role(ctx, function):
        discs.append("library_role")
    return tuple(discs)


def combined_shape_discriminators(ctx, functions) -> tuple[str, ...]:
    from detector.analysis import roles

    fns = list(functions)
    discs: list[str] = []
    if fns:
        per = [set(shape_discriminators(ctx, fn)) for fn in fns]
        shared = set.intersection(*per) if per else set()
        if "managed_role" in shared:
            discs.append("managed_role")
        if "library_role" in shared:
            discs.append("library_role")
    if roles.issuer_token(ctx):
        discs.append("issuer_token")
    return tuple(discs)


def make_finding(
    rule_id: str,
    *,
    contract: str,
    function: str,
    lines: Iterable[int],
    reasoning: str,
    discriminators: tuple[str, ...] = (),
    severity: str | None = None,
) -> Finding:
    family, base_severity = CATALOG[rule_id]
    return Finding(
        rule_id=rule_id,
        family=family,
        severity=severity if severity is not None else base_severity,
        contract=contract,
        function=function,
        lines=tuple(lines),
        reasoning=reasoning,
        base_severity=base_severity,
        discriminators=tuple(discriminators),
        counts_for_escalation=True,
    )
