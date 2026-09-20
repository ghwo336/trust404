"""Family C: mutable fee recipient and privileged balance leaks."""

from __future__ import annotations

from typing import Any

from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, Index
from slither.slithir.operations.binary import BinaryType

from detector.analysis import roles
from detector.analysis._ir import (
    MSG_SENDER,
    MSG_VALUE,
    assert_never,
    closure_with_zero_params,
    depends,
    false_son,
    fn_ir,
    function_sort_key,
    guarded_nodes,
    is_address_var,
    is_ctor,
    is_modifier,
    is_msg_sender,
    is_msg_value,
    is_return_node,
    is_this_expr,
    iter_internal_callees,
    reachable_from,
    resolve_state_dest,
    root_state,
    true_son,
    unique_functions,
)
from detector.analysis.balances import balance_writes
from detector.analysis.context import ContractContext
from detector.analysis.flows import is_whole_pot, token_out_calls, value_sends
from detector.analysis.privilege import auth_atoms, branch_atoms, is_privileged
from detector.analysis.transfer_path import _path_meta
from detector.model import Finding
from detector.rules.base import make_finding

_FROM_KEYS = frozenset({"from", "msg.sender"})


def _source_lines(obj: Any) -> tuple[int, ...]:
    mapping = getattr(obj, "source_mapping", None)
    if mapping is None:
        return ()
    lines = getattr(mapping, "lines", None)
    if not lines:
        return ()
    return tuple(int(n) for n in lines)


def _emit(
    rule_id: str,
    ctx: ContractContext,
    function: Function,
    node: Any,
    reasoning: str,
    discriminators: tuple[str, ...] = (),
) -> Finding:
    return make_finding(
        rule_id,
        contract=ctx.contract.name,
        function=function.name,
        lines=_source_lines(node) or _source_lines(function),
        reasoning=reasoning,
        discriminators=discriminators,
    )


def _roles_for(ctx: ContractContext, function: Function) -> dict:
    return dict(_path_meta(ctx).roles.get(id(function), {}))


def _shape_discs(ctx: ContractContext, function: Function) -> list[str]:
    found: list[str] = []
    if roles.issuer_token(ctx):
        found.append("issuer_token")
    for atom in auth_atoms(function):
        if atom.auth_var is not None and roles.managed_role(ctx, atom.auth_var):
            found.append("managed_role")
            break
    else:
        for atom, _node in branch_atoms(function):
            if atom.auth_var is not None and roles.managed_role(ctx, atom.auth_var):
                found.append("managed_role")
                break
    return found


def _closure(function: Function) -> list[Function]:
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


def _key_state(write, function: Function) -> StateVariable | None:
    key = write.key
    if isinstance(key, StateVariable):
        return key
    dest = resolve_state_dest(key, function) if key is not None else None
    if dest is not None:
        return dest
    return root_state(key, function) if key is not None else None


def _pw_address(ctx: ContractContext, var: StateVariable | None) -> bool:
    if var is None:
        return False
    if var not in ctx.privileged_writable:
        return False
    return is_address_var(var)


def _sender_dependent(var: Any, function: Function) -> bool:
    if var is None:
        return False
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if is_msg_sender(var) or is_msg_sender(cur):
        return True
    return depends(var, MSG_SENDER, function) or depends(cur, MSG_SENDER, function)


def _sender_key(write, function: Function) -> bool:
    if write.key_source == "msg.sender":
        return True
    return _sender_dependent(write.key, function)


def _allowance_nodes(function: Function, allowance_vars: tuple[StateVariable, ...]) -> set[Any]:
    if not allowance_vars:
        return set()
    ids = {id(var) for var in allowance_vars}
    found: set[Any] = set()
    for node in function.nodes:
        if any(id(sv) in ids for sv in node.state_variables_read):
            found.add(node)
    return found


def _false_only(if_node) -> set[Any]:
    false_nodes = reachable_from(false_son(if_node), banned=(if_node,))
    true_nodes = reachable_from(true_son(if_node), banned=(if_node,))
    return false_nodes - true_nodes


def _allowance_skipped(function: Function, allowance_vars: tuple[StateVariable, ...]) -> bool:
    reads = _allowance_nodes(function, allowance_vars)
    if not reads:
        return True
    for _atom, if_node in branch_atoms(function):
        true_only = guarded_nodes(if_node)
        false_only = _false_only(if_node)
        if reads <= true_only or reads <= false_only:
            return True
    return False


def _guard_functions(function: Function) -> list[Function]:
    out = [function]
    for mod in function.modifiers:
        if isinstance(mod, Function):
            out.append(mod)
    return out


def _neq_this(function: Function) -> bool:
    for site in _guard_functions(function):
        for node in site.nodes:
            for ir in node.irs:
                if not isinstance(ir, Binary) or ir.type != BinaryType.NOT_EQUAL:
                    continue
                if is_this_expr(ir.variable_left, site) or is_this_expr(ir.variable_right, site):
                    return True
    return False


def fee_addr_mutable(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    def add(item: Finding) -> None:
        key = (item.function, item.lines)
        if key in seen:
            return
        seen.add(key)
        findings.append(item)

    path = sorted(ctx.transfer_path, key=function_sort_key)
    hits: list[tuple[Function, Any, StateVariable]] = []
    for function in path:
        if is_ctor(function):
            continue
        param_roles = _roles_for(ctx, function)
        for write in balance_writes(function, ctx.bindings, param_roles):
            if write.kind != "credit":
                continue
            if write.key_source != "state":
                continue
            key_var = _key_state(write, function)
            if not _pw_address(ctx, key_var):
                continue
            assert key_var is not None
            hits.append((function, write.node, key_var))
        for node, to_expr, _value, kind in value_sends(function):
            if kind == "selfdestruct":
                continue
            if kind not in ("transfer", "send", "call_value"):
                assert_never(kind)
            dest = resolve_state_dest(to_expr, function)
            if not _pw_address(ctx, dest):
                continue
            assert dest is not None
            hits.append((function, node, dest))
        for node, _call, _source, to_expr, _amount in token_out_calls(function, ctx.bindings):
            dest = resolve_state_dest(to_expr, function)
            if not _pw_address(ctx, dest):
                continue
            assert dest is not None
            hits.append((function, node, dest))

    for function, node, var in hits:
        writers = sorted(
            ctx.privileged_writable.get(var, []),
            key=lambda pw: (function_sort_key(pw.function), _source_lines(pw.node)),
        )
        writer_names = ", ".join(pw.function.name for pw in writers) or "?"
        add(
            _emit(
                "FEE_ADDR_MUTABLE",
                ctx,
                function,
                node,
                f"{var.name} is a privileged-writable credit/send destination on the transfer path (writers: {writer_names})",
            )
        )
        for pw in writers:
            add(
                _emit(
                    "FEE_ADDR_MUTABLE",
                    ctx,
                    pw.function,
                    pw.node,
                    f"{pw.function.name} writes privileged-writable {var.name} used as a transfer-path fee destination",
                )
            )
    return findings


def leak_arbitrary_transferfrom(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()
    allowance = ctx.bindings.allowance_vars

    def add(item: Finding) -> None:
        key = (item.function, item.lines)
        if key in seen:
            return
        seen.add(key)
        findings.append(item)

    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        function_mode = is_privileged(function)
        branch_mode = bool(branch_atoms(function))
        if not function_mode and not branch_mode:
            continue
        if function_mode:
            allowance_ok = True
            for site in _closure(function):
                if _allowance_nodes(site, allowance) and not _allowance_skipped(site, allowance):
                    allowance_ok = False
                    break
        else:
            allowance_ok = _allowance_skipped(function, allowance)
            for site in _closure(function):
                if site is function:
                    continue
                if _allowance_nodes(site, allowance) and not _allowance_skipped(site, allowance):
                    # MiniMe: allowance lives in transferFrom, debit in callee.
                    continue
        if not allowance_ok:
            continue
        for site, zero_params in closure_with_zero_params(function):
            param_roles = _roles_for(ctx, site)
            for write in balance_writes(site, ctx.bindings, param_roles):
                if write.kind != "debit":
                    continue
                if _sender_key(write, site):
                    continue
                if write.key is not None and id(write.key) in zero_params:
                    continue
                discs = tuple(_shape_discs(ctx, function))
                add(
                    _emit(
                        "LEAK_ARBITRARY_TRANSFERFROM",
                        ctx,
                        function,
                        write.node,
                        f"{function.name} reaches a bound-balance debit at a non-sender key without a dominating allowance read",
                        discs,
                    )
                )
    return findings


def leak_exempt_path(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    def add(item: Finding) -> None:
        key = (item.function, item.lines)
        if key in seen:
            return
        seen.add(key)
        findings.append(item)

    for function in sorted(ctx.transfer_path, key=function_sort_key):
        if is_ctor(function):
            continue
        param_roles = _roles_for(ctx, function)
        writes = balance_writes(function, ctx.bindings, param_roles)
        for atom, if_node in branch_atoms(function):
            if atom.auth_var not in ctx.privileged_writable:
                continue
            guarded = guarded_nodes(if_node)
            credits = [w for w in writes if w.kind == "credit" and w.node in guarded]
            from_debits = [
                w
                for w in writes
                if w.kind == "debit" and w.key_source in _FROM_KEYS and w.node in guarded
            ]
            if not credits or from_debits:
                continue
            if not any(is_return_node(node) for node in guarded):
                continue
            add(
                _emit(
                    "LEAK_EXEMPT_PATH",
                    ctx,
                    function,
                    if_node,
                    f"{function.name} takes a privileged-writable branch on {atom.auth_var.name} that credits a bound balance and skips the from-debit",
                )
            )
    return findings


def _caller_ledger_amount(amount: Any, function: Function, ctx: ContractContext) -> bool:
    if amount is None:
        return False
    helper = fn_ir(function)
    cur = helper.unwrap(amount)
    if is_msg_value(amount) or is_msg_value(cur):
        return True
    if depends(amount, MSG_VALUE, function) or depends(cur, MSG_VALUE, function):
        return True
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Index) or ir.lvalue is None:
                continue
            if not _sender_dependent(ir.variable_right, function):
                continue
            if amount is ir.lvalue or cur is ir.lvalue or depends(amount, ir.lvalue, function):
                return True
    return any(depends(amount, bal, function) and _sender_dependent(amount, function) for bal in ctx.bindings.balance_vars)


def _unbounded_drain_amount(amount: Any, function: Function, ctx: ContractContext) -> bool:
    if amount is None or _caller_ledger_amount(amount, function, ctx):
        return False
    helper = fn_ir(function)
    cur = helper.unwrap(amount)
    params = list(function.parameters or [])
    if any(amount is p or cur is p or depends(amount, p, function) for p in params):
        return True
    return root_state(amount, function) is not None or root_state(cur, function) is not None


def leak_priv_sweep(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        if not is_privileged(function):
            continue
        discs = list(_shape_discs(ctx, function))
        hit = False
        impact = function
        for site in _closure(function):
            for node, _to, value, kind in value_sends(site):
                if kind == "selfdestruct":
                    continue
                if kind not in ("transfer", "send", "call_value"):
                    assert_never(kind)
                if not is_whole_pot(value, site) and not _unbounded_drain_amount(value, site, ctx):
                    continue
                hit = True
                impact = site
                if not roles.has_custody(ctx) and "no_custody" not in discs:
                    discs.append("no_custody")
                _ = node
            for node, _call, source, _to, _amount in token_out_calls(site, ctx.bindings):
                if source == "state":
                    hit = True
                    impact = site
                elif source == "param":
                    hit = True
                    impact = site
                    if (_neq_this(function) or not ctx.bindings.balance_vars) and "foreign_only" not in discs:
                        discs.append("foreign_only")
                elif source == "this":
                    hit = True
                    impact = site
                else:
                    assert_never(source)
                _ = node
        if not hit:
            continue
        if function.name in seen:
            continue
        seen.add(function.name)
        findings.append(
            _emit(
                "LEAK_PRIV_SWEEP",
                ctx,
                function,
                impact,
                f"{function.name} is a privileged sweep of contract ETH or an external token",
                tuple(discs),
            )
        )
    return findings


RULES = [
    fee_addr_mutable,
    leak_arbitrary_transferfrom,
    leak_exempt_path,
    leak_priv_sweep,
]
