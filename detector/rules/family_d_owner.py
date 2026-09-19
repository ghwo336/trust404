"""Family D: hidden roles, fake renounce, nonstandard reassignment, tx.origin."""

from __future__ import annotations

from detector.analysis import privilege, roles
from detector.analysis._ir import (
    fn_ir,
    function_sort_key,
    is_address_var,
    is_ctor,
    is_modifier,
    is_msg_sender,
    iter_internal_callees,
    node_sort_key,
    root_state,
    unique_functions,
    var_sort_key,
)
from detector.analysis.context import ContractContext
from detector.analysis.privilege import unprivileged_writers
from detector.model import Finding
from detector.rules.base import contract_name, function_name, make_finding, node_lines
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Assignment, Unary
from slither.slithir.operations.unary import UnaryType
from slither.slithir.variables.constant import Constant


def _cname(ctx: ContractContext) -> str:
    return contract_name(ctx.contract)


def _gating_auth(ctx: ContractContext) -> list[StateVariable]:
    used: set[StateVariable] = set()
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn):
            continue
        if not privilege.is_privileged(fn):
            continue
        for atom in privilege.auth_atoms(fn):
            if atom.auth_var is not None:
                used.add(atom.auth_var)
    return sorted(used, key=var_sort_key)


def _gated_functions(ctx: ContractContext, auth_var: StateVariable) -> list:
    out = []
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if not privilege.is_privileged(fn):
            continue
        if any(atom.auth_var is auth_var for atom in privilege.auth_atoms(fn)):
            out.append(fn)
    out.sort(key=function_sort_key)
    return out


def OWN_HIDDEN_ROLE(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    for var in _gating_auth(ctx):
        if privilege.is_exposed(ctx.contract, var):
            continue
        gated = _gated_functions(ctx, var)
        if not gated:
            continue
        fn = gated[0]
        atoms = [a for a in privilege.auth_atoms(fn) if a.auth_var is var]
        atoms.sort(key=lambda atom: (node_sort_key(atom.node), atom.kind))
        node = atoms[0].node if atoms else fn.entry_point
        out.append(
            make_finding(
                "OWN_HIDDEN_ROLE",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(node) if node is not None else (),
                reasoning=f"{var.name} gates {function_name(fn)} and is not exposed",
            )
        )
    return out


def _is_zero(var, function) -> bool:
    if var is None:
        return False
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    for cand in (var, cur):
        if isinstance(cand, Constant):
            val = cand.value
            return val == 0 or val is False
    ir = helper.def_of(var)
    if ir is not None and ir.__class__.__name__ == "TypeConversion":
        return _is_zero(getattr(ir, "variable", None), function)
    return False


def _is_delete(ir) -> bool:
    if not isinstance(ir, Unary):
        return False
    name = str(getattr(ir.type, "name", ir.type)).upper()
    return "DELETE" in name or ir.type == getattr(UnaryType, "DELETE", None)


def _is_nonzero_literal_or_sender(var, function) -> bool:
    if var is None:
        return False
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if is_msg_sender(var) or is_msg_sender(cur):
        return True
    if _is_zero(var, function):
        return False
    for cand in (var, cur):
        if isinstance(cand, Constant):
            val = cand.value
            if isinstance(val, int) and val != 0:
                return True
            if isinstance(val, str) and val not in ("", "0"):
                return True
    ir = helper.def_of(var)
    if ir is not None and ir.__class__.__name__ == "TypeConversion":
        inner = getattr(ir, "variable", None)
        if _is_zero(inner, function):
            return False
        if isinstance(inner, Constant) or _is_nonzero_literal_or_sender(inner, function):
            return True
    return False


def _auth_assignments(function, auth) -> list[tuple]:
    """Return (var, node, kind) where kind is zero|nonzero|other."""
    found: list[tuple] = []
    stack = [function]
    seen: set[int] = set()
    while stack:
        fn = stack.pop()
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        helper = fn_ir(fn)
        for node in fn.nodes:
            for ir in node.irs:
                if _is_delete(ir):
                    root = root_state(getattr(ir, "rvalue", None), fn) or root_state(
                        getattr(ir, "lvalue", None), fn
                    )
                    if isinstance(root, StateVariable) and root in auth and is_address_var(root):
                        found.append((root, node, "zero"))
                    continue
                if not isinstance(ir, Assignment):
                    continue
                root = ir.lvalue if ir.lvalue in auth else root_state(ir.lvalue, fn)
                if not isinstance(root, StateVariable) or root not in auth:
                    continue
                if not is_address_var(root):
                    found.append((root, node, "other"))
                    continue
                rval = helper.unwrap(ir.rvalue)
                if _is_zero(ir.rvalue, fn) or _is_zero(rval, fn):
                    found.append((root, node, "zero"))
                elif _is_nonzero_literal_or_sender(ir.rvalue, fn):
                    found.append((root, node, "nonzero"))
                else:
                    found.append((root, node, "other"))
        for _, callee in iter_internal_callees(fn):
            stack.append(callee)
    return found


def OWN_FAKE_RENOUNCE(ctx: ContractContext) -> list[Finding]:
    gating = _gating_auth(ctx)
    if not gating:
        return []
    out: list[Finding] = []
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if not privilege.is_privileged(fn):
            continue
        assigns = _auth_assignments(fn, gating)
        if not assigns:
            continue
        zeroed = {var for var, _node, kind in assigns if kind == "zero"}
        if not zeroed:
            continue
        uncleared = sorted((var for var in gating if var not in zeroed), key=var_sort_key)
        nonzero = [item for item in assigns if item[2] == "nonzero"]
        if not uncleared and not nonzero:
            continue
        zero_nodes = [n for _v, n, k in assigns if k == "zero"]
        zero_nodes.sort(key=node_sort_key)
        node = zero_nodes[0]
        names = ", ".join(v.name for v in uncleared) if uncleared else "nonzero write"
        extra = ("two_step_handoff",) if roles.two_step_handoff(ctx, fn) else ()
        out.append(
            make_finding(
                "OWN_FAKE_RENOUNCE",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(node),
                reasoning=f"{function_name(fn)} zeros an auth var while {names} remains",
                discriminators=extra,
            )
        )
    return out


def OWN_REASSIGN_NONSTD(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    gating = _gating_auth(ctx)
    seen: set[tuple[str, str]] = set()
    for var in gating:
        for fn in unprivileged_writers(ctx.contract, var):
            if not ctx.is_from_input_root(fn):
                continue
            extra_list: list[str] = []
            if roles.one_shot_initializer(fn):
                extra_list.append("one_shot_initializer")
            if roles.two_step_handoff(ctx, fn):
                extra_list.append("two_step_handoff")
            extra = tuple(extra_list)
            key = (function_name(fn), var.name)
            if key in seen:
                continue
            seen.add(key)
            node = fn.entry_point
            for n in fn.nodes:
                if var in n.state_variables_written:
                    node = n
                    break
            out.append(
                make_finding(
                    "OWN_REASSIGN_NONSTD",
                    contract=_cname(ctx),
                    function=function_name(fn),
                    lines=node_lines(node) if node is not None else (),
                    reasoning=f"non-privileged {function_name(fn)} writes auth var {var.name}",
                    discriminators=extra,
                )
            )
        for fn in unique_functions(ctx.contract):
            if is_ctor(fn) or is_modifier(fn):
                continue
            if not ctx.is_from_input_root(fn):
                continue
            atoms = privilege.auth_atoms(fn)
            if any(atom.kind == "eq_self" for atom in atoms):
                continue
            gated_by_var = any(atom.auth_var is var for atom in atoms)
            if gated_by_var:
                continue
            assigns = _auth_assignments(fn, {var})
            hits = [item for item in assigns if item[2] == "nonzero"]
            hits.sort(key=lambda item: node_sort_key(item[1]))
            if not hits:
                continue
            extra_list = []
            if roles.one_shot_initializer(fn):
                extra_list.append("one_shot_initializer")
            if roles.two_step_handoff(ctx, fn):
                extra_list.append("two_step_handoff")
            extra = tuple(extra_list)
            key = (function_name(fn), var.name)
            if key in seen:
                continue
            seen.add(key)
            node = hits[0][1]
            out.append(
                make_finding(
                    "OWN_REASSIGN_NONSTD",
                    contract=_cname(ctx),
                    function=function_name(fn),
                    lines=node_lines(node),
                    reasoning=(
                        f"{function_name(fn)} assigns a literal or msg.sender "
                        f"to {var.name} without being gated by it"
                    ),
                    discriminators=extra,
                )
            )
    return out


def OWN_TX_ORIGIN(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        atoms = [a for a in privilege.auth_atoms(fn) if a.sender_source == "tx.origin"]
        if not atoms:
            continue
        atoms.sort(
            key=lambda atom: (
                node_sort_key(atom.node),
                atom.kind,
                "" if atom.auth_var is None else atom.auth_var.name,
            )
        )
        out.append(
            make_finding(
                "OWN_TX_ORIGIN",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(atoms[0].node),
                reasoning=f"{function_name(fn)} auth atom uses tx.origin vs {atoms[0].auth_var.name}",
            )
        )
    return out


RULES = [
    OWN_HIDDEN_ROLE,
    OWN_FAKE_RENOUNCE,
    OWN_REASSIGN_NONSTD,
    OWN_TX_ORIGIN,
]
