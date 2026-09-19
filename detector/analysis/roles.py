"""Contract-level role / issuer / custody / ungate shapes (research §6)."""

from __future__ import annotations

from typing import Any

from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    EventCall,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Send,
    Transfer,
    Unary,
)
from slither.slithir.operations.unary import UnaryType

from detector.analysis._ir import (
    MSG_VALUE,
    assert_never,
    branch_reverts_before_write,
    callee_of,
    constant_bool,
    depends,
    false_son,
    fn_ir,
    is_bool_type,
    is_ctor,
    is_if_node,
    is_modifier,
    is_msg_value,
    is_require_assert_node,
    is_uint_type,
    iter_internal_callees,
    root_state,
    sorted_vars,
    true_son,
    unique_functions,
    values_feeding_condition,
)
from detector.analysis.balances import balance_writes
from detector.analysis.privilege import auth_atoms, is_privileged, privileged_writes
from detector.analysis.transfer_path import EndNode


def library_role(ctx: Any, function: Function) -> bool:
    atoms = auth_atoms(function)
    if not atoms:
        return False
    return all(not ctx.is_from_input_root(atom.node) for atom in atoms)


def one_shot_initializer(function: Function) -> bool:
    written = {v for v in function.state_variables_written} | {
        v for v in function.all_state_variables_written()
    }
    flags = {v for v in written if is_bool_type(v.type) or is_uint_type(v.type)}
    if not flags:
        return False
    for node in function.nodes:
        is_end = is_require_assert_node(node)
        if is_if_node(node) and (
            branch_reverts_before_write(true_son(node))
            or branch_reverts_before_write(false_son(node))
        ):
            is_end = True
        if not is_end:
            continue
        for sv in node.state_variables_read:
            if sv in flags:
                return True
        for val in values_feeding_condition(node):
            root = root_state(val, function)
            if root in flags or val in flags:
                return True
    return False


def managed_role(ctx: Any, auth_var: StateVariable) -> bool:
    writers: list[Function] = []
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if one_shot_initializer(fn):
            continue
        if auth_var in fn.state_variables_written or auth_var in fn.all_state_variables_written():
            writers.append(fn)
    if not writers:
        return False
    for fn in writers:
        if not is_privileged(fn):
            return False
        others = [atom.auth_var for atom in auth_atoms(fn) if atom.auth_var is not auth_var]
        if not others:
            return False
    return True


def _function_and_callees(function: Function) -> list[Function]:
    out: list[Function] = []
    stack = [function]
    seen: set[int] = set()
    while stack:
        fn = stack.pop()
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        out.append(fn)
        for _, callee in iter_internal_callees(fn):
            stack.append(callee)
    return out


def _emits_amount(function: Function) -> bool:
    uints = [p for p in function.parameters if is_uint_type(p.type)]
    if not uints:
        return False
    for fn in _function_and_callees(function):
        ctx_fn = function if fn is function else fn
        for node in fn.nodes:
            for ir in node.irs:
                if not isinstance(ir, EventCall):
                    continue
                for arg in ir.arguments or []:
                    if arg in uints:
                        return True
                    if fn is function and any(depends(arg, u, function) for u in uints):
                        return True
                    if fn is not function:
                        # Callee: argument may be the callee's own uint param mapped from amount.
                        callee_uints = [p for p in fn.parameters if is_uint_type(p.type)]
                        if arg in callee_uints or any(depends(arg, u, fn) for u in callee_uints):
                            return True
                    _ = ctx_fn
    return False


def issuer_token(ctx: Any) -> bool:
    bindings = ctx.bindings
    if not bindings.balance_vars:
        return False
    for auth in sorted_vars(ctx.auth_vars):
        credit_ok = False
        debit_ok = False
        for fn in unique_functions(ctx.contract):
            if is_ctor(fn) or is_modifier(fn) or not is_privileged(fn):
                continue
            if not any(atom.auth_var is auth for atom in auth_atoms(fn)):
                continue
            writes = []
            for site in _function_and_callees(fn):
                writes.extend(balance_writes(site, bindings))
            non_sender = {"param", "state", "this"}
            has_credit = any(
                w.kind in ("credit", "set") and w.key_source in non_sender for w in writes
            )
            has_debit = any(w.kind == "debit" and w.key_source in non_sender for w in writes)
            if has_credit and _emits_amount(fn):
                credit_ok = True
            if has_debit and _emits_amount(fn):
                debit_ok = True
        if credit_ok and debit_ok:
            return True
    return False


def _forwards_msg_value(function: Function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, (Transfer, Send)):
                val = ir.call_value
                if is_msg_value(val) or depends(val, MSG_VALUE, function):
                    return True
            elif isinstance(ir, (LowLevelCall, HighLevelCall)) and ir.call_value is not None:
                val = ir.call_value
                if is_msg_value(val) or depends(val, MSG_VALUE, function):
                    return True
    return False


def has_custody(ctx: Any) -> bool:
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if not (fn.payable or fn.is_receive or fn.is_fallback):
            continue
        if is_privileged(fn):
            continue
        if _forwards_msg_value(fn):
            continue
        return True
    return False


def _var_negated_in(node, function: Function, var: StateVariable) -> bool | None:
    """Return True if `var` is negated in the condition, False if used raw, None if unused."""
    helper = fn_ir(function)
    feeding = values_feeding_condition(node)
    negated = False
    used = False
    for ir in node.irs:
        if isinstance(ir, Unary) and ir.type == UnaryType.BANG:
            inner = helper.unwrap(ir.rvalue)
            inner_root = root_state(inner, function) or root_state(ir.rvalue, function)
            call = helper.def_of(ir.rvalue)
            returns_var = False
            if isinstance(call, (InternalCall, LibraryCall)):
                callee = callee_of(call)
                if callee is not None:
                    if var in callee.state_variables_read or var in (callee.return_values or []):
                        returns_var = True
                    if any(rv is var or root_state(rv, callee) is var for rv in (callee.return_values or [])):
                        returns_var = True
            if inner is var or ir.rvalue is var or inner_root is var or returns_var:
                negated = True
                used = True
        if isinstance(ir, (InternalCall, LibraryCall)):
            callee = callee_of(ir)
            if callee is not None and (
                var in (callee.return_values or [])
                or any(root_state(rv, callee) is var for rv in (callee.return_values or []))
                or var in callee.state_variables_read
            ):
                used = True
    if var in node.state_variables_read:
        used = True
    for val in feeding:
        if val is var or root_state(val, function) is var:
            used = True
    if not used:
        return None
    return negated


def _permissive_value(end_node: EndNode, var: StateVariable) -> bool | None:
    node = end_node.node
    function = node.function
    negated = _var_negated_in(node, function, var)
    if negated is None:
        return None
    kind = end_node.kind
    var_true_makes_cond_true = not negated
    if kind in ("require", "assert"):
        return var_true_makes_cond_true
    if kind == "if_revert":
        return not var_true_makes_cond_true
    if kind == "if_return_before_write":
        return None
    assert_never(kind)
    return None


def _write_can_set(pw, permissive: bool) -> bool:
    node = pw.node
    var = pw.var
    helper = fn_ir(pw.function)
    for ir in node.irs:
        if isinstance(ir, Assignment) and (ir.lvalue is var or root_state(ir.lvalue, pw.function) is var):
            flag = constant_bool(ir.rvalue)
            if flag is None:
                flag = constant_bool(helper.unwrap(ir.rvalue))
            if flag is None:
                return True
            return flag is permissive
        if isinstance(ir, Unary) and ir.type == UnaryType.BANG:
            # assigned via TMP = !param; var := TMP handled as Assignment of non-constant
            continue
    # Direct `_paused = true` is Assignment. If we missed, inspect all IRS.
    for ir in node.irs:
        lval = getattr(ir, "lvalue", None)
        if lval is var:
            rval = getattr(ir, "rvalue", None)
            flag = constant_bool(rval)
            if flag is None:
                return True
            return flag is permissive
    return False


def ungate_exists(ctx: Any, var: StateVariable, end_node: EndNode) -> bool:
    if not is_bool_type(var.type):
        return False
    permissive = _permissive_value(end_node, var)
    if permissive is None:
        return False
    for pw in privileged_writes(ctx.contract):
        if pw.var is not var:
            continue
        if pw.mode not in ("function", "branch"):
            assert_never(pw.mode)
        if _write_can_set(pw, permissive):
            return True
    return False
