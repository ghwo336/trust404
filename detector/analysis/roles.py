"""Contract-level role / issuer / custody / ungate shapes (research §6)."""

from __future__ import annotations

from typing import Any

from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Assignment,
    Binary,
    EventCall,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Return,
    Send,
    Transfer,
    Unary,
)
from slither.slithir.operations.binary import BinaryType
from slither.slithir.operations.unary import UnaryType
from slither.slithir.variables.constant import Constant

from detector.analysis._ir import (
    MSG_SENDER,
    MSG_VALUE,
    assert_never,
    branch_reverts_before_write,
    callee_of,
    constant_bool,
    depends,
    false_son,
    fn_ir,
    index_chain,
    is_addr_bool_mapping,
    is_bool_type,
    is_ctor,
    is_externally_callable,
    is_if_node,
    is_modifier,
    is_msg_sender,
    is_msg_value,
    is_require_assert_node,
    is_uint_type,
    iter_internal_callees,
    returns_sender_source,
    root_state,
    sorted_vars,
    true_son,
    unique_functions,
    values_feeding_condition,
)
from detector.analysis.balances import balance_writes
from detector.analysis.privilege import (
    auth_atoms,
    is_privileged,
    privileged_writable,
    privileged_writes,
)


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


def _returns_map_field(callee: Function, auth_var: StateVariable) -> bool:
    """True if `callee` returns a non-bool field loaded from `auth_var` (adminRole)."""
    values = list(callee.return_values or [])
    for node in callee.nodes:
        for ir in node.irs:
            if isinstance(ir, Return):
                values.extend(ir.values)
    if not values or any(is_bool_type(getattr(val, "type", None)) for val in values):
        return False
    return any(root_state(val, callee) is auth_var for val in values)


def _role_admin_gate(function: Function, auth_var: StateVariable) -> bool:
    """OZ AccessControl: gated by hasRole(getRoleAdmin(role), sender) — same mapping,
    key is a non-bool field read of that mapping, not a constant role id."""
    if not any(a.auth_var is auth_var and a.kind == "map_bool" for a in auth_atoms(function)):
        return False
    for site in _function_and_callees(function):
        for node in site.nodes:
            for ir in node.irs:
                if not isinstance(ir, (InternalCall, LibraryCall)):
                    continue
                callee = callee_of(ir)
                if callee is not None and _returns_map_field(callee, auth_var):
                    return True
    return False


def _is_sender_expr(var: Any, function: Function) -> bool:
    helper = fn_ir(function)
    if is_msg_sender(var) or is_msg_sender(helper.unwrap(var)):
        return True
    ir = helper.def_of(var)
    if isinstance(ir, (InternalCall, LibraryCall)):
        callee = callee_of(ir)
        if callee is not None and returns_sender_source(callee) == "msg.sender":
            return True
    return False


def _sender_eq_params(function: Function) -> set:
    found: set = set()
    for site in _function_and_callees(function):
        helper = fn_ir(site)
        params = set(site.parameters or [])
        for node in site.nodes:
            for ir in node.irs:
                if not isinstance(ir, Binary) or ir.type != BinaryType.EQUAL:
                    continue
                left, right = ir.variable_left, ir.variable_right
                for side, other in ((left, right), (right, left)):
                    if not _is_sender_expr(side, site):
                        continue
                    cur = helper.unwrap(other)
                    if other in params or cur in params:
                        found.add(other)
                        found.add(cur)
    pending = True
    while pending:
        pending = False
        for site in _function_and_callees(function):
            helper = fn_ir(site)
            for ir, callee in iter_internal_callees(site):
                args = list(ir.arguments or [])
                dests = list(callee.parameters or [])
                for idx, param in enumerate(dests):
                    if idx >= len(args):
                        break
                    arg = args[idx]
                    if arg in found or helper.unwrap(arg) in found:
                        if param not in found:
                            found.add(param)
                            pending = True
    return found


def _sender_slot_only(function: Function, auth_var: StateVariable) -> bool:
    sender_params = _sender_eq_params(function)
    wrote_sender = False
    wrote_other = False
    for site in _function_and_callees(function):
        helper = fn_ir(site)
        for node in site.nodes:
            for ir in node.irs:
                if not isinstance(ir, Assignment):
                    continue
                if root_state(ir.lvalue, site) is not auth_var:
                    continue
                _root, keys = index_chain(ir.lvalue, site)
                if keys and any(
                    is_msg_sender(key)
                    or depends(key, MSG_SENDER, site)
                    or key in sender_params
                    or helper.unwrap(key) in sender_params
                    for key in keys
                ):
                    wrote_sender = True
                else:
                    wrote_other = True
    return wrote_sender and not wrote_other


def managed_role(ctx: Any, auth_var: StateVariable) -> bool:
    writers: list[Function] = []
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn) or is_modifier(fn) or not is_externally_callable(fn):
            continue
        if one_shot_initializer(fn):
            continue
        if auth_var not in fn.state_variables_written and auth_var not in fn.all_state_variables_written():
            continue
        if not is_privileged(fn) and _sender_slot_only(fn, auth_var):
            continue
        writers.append(fn)
    if not writers:
        return False
    for fn in writers:
        if not is_privileged(fn):
            return False
        others = [
            atom.auth_var
            for atom in auth_atoms(fn)
            if atom.auth_var is not None and atom.auth_var is not auth_var
        ]
        if others or _role_admin_gate(fn, auth_var):
            continue
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


def _permissive_value(end_node: Any, var: StateVariable) -> bool | None:
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


def ungate_exists(ctx: Any, var: StateVariable, end_node: Any) -> bool:
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


def privileged_blocking_writable(ctx: Any, var: StateVariable, end_node: Any) -> bool:
    """Gate var: a privileged writer can store the blocking polarity, even with an
    unprivileged writer. Numeric/time/address gates keep privileged_writable exclusivity."""
    if var.is_constant or var.is_immutable:
        return False
    if is_bool_type(var.type) or is_addr_bool_mapping(var):
        permissive = _permissive_value(end_node, var)
        if permissive is None:
            return False
        blocking = not permissive
        return any(pw.var is var and _write_can_set(pw, blocking) for pw in privileged_writes(ctx.contract))
    return var in privileged_writable(ctx.contract)


def _is_zero_value(var: Any, function: Function) -> bool:
    if var is None:
        return False
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    for cand in (var, cur):
        if isinstance(cand, Constant) and (cand.value == 0 or cand.value is False):
            return True
    ir = helper.def_of(var)
    if ir is not None and type(ir).__name__ == "TypeConversion":
        return _is_zero_value(getattr(ir, "variable", None), function)
    return False


def _clears_var(function: Function, var: StateVariable) -> bool:
    for site in _function_and_callees(function):
        helper = fn_ir(site)
        for node in site.nodes:
            for ir in node.irs:
                if isinstance(ir, Unary):
                    name = str(getattr(ir.type, "name", ir.type)).upper()
                    if "DELETE" in name:
                        root = root_state(getattr(ir, "lvalue", None), site) or root_state(
                            getattr(ir, "rvalue", None), site
                        )
                        if root is var:
                            return True
                if not isinstance(ir, Assignment):
                    continue
                root = ir.lvalue if ir.lvalue is var else root_state(ir.lvalue, site)
                if root is var and (
                    _is_zero_value(ir.rvalue, site) or _is_zero_value(helper.unwrap(ir.rvalue), site)
                ):
                    return True
    return False


def _assigns_sender_or_p(function: Function, pending: StateVariable, auth: set) -> bool:
    for site in _function_and_callees(function):
        helper = fn_ir(site)
        for node in site.nodes:
            for ir in node.irs:
                if not isinstance(ir, Assignment):
                    continue
                root = ir.lvalue if isinstance(ir.lvalue, StateVariable) else root_state(ir.lvalue, site)
                if not isinstance(root, StateVariable) or root is pending or root not in auth:
                    continue
                rval = helper.unwrap(ir.rvalue)
                if is_msg_sender(ir.rvalue) or is_msg_sender(rval):
                    return True
                if rval is pending or ir.rvalue is pending or root_state(rval, site) is pending:
                    return True
                if depends(ir.rvalue, MSG_SENDER, site) or depends(rval, MSG_SENDER, site):
                    return True
                if depends(ir.rvalue, pending, site) or depends(rval, pending, site):
                    return True
    return False


def two_step_handoff(ctx: Any, function: Function) -> bool:
    atoms = [a for a in auth_atoms(function) if a.auth_var is not None]
    if not atoms:
        return False
    auth_set = {v for v in ctx.auth_vars if v is not None}
    seen: set[int] = set()
    for atom in atoms:
        pending = atom.auth_var
        if pending is None or id(pending) in seen:
            continue
        seen.add(id(pending))
        shared = False
        for fn in unique_functions(ctx.contract):
            if fn is function or is_ctor(fn) or is_modifier(fn) or not is_privileged(fn):
                continue
            if any(a.auth_var is pending for a in auth_atoms(fn)):
                shared = True
                break
        if shared:
            continue
        if _assigns_sender_or_p(function, pending, auth_set) and _clears_var(function, pending):
            return True
    return False
