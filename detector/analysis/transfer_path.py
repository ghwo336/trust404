"""ERC-20 transfer-path, end nodes, and gate reads (research §5 predicate 3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from slither.core.cfg.node import Node
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable
from slither.slithir.operations import (
    Binary,
    Index,
    InternalCall,
    LibraryCall,
)
from slither.slithir.operations.binary import BinaryType

from detector.analysis._ir import (
    SIG_TRANSFER,
    SIG_TRANSFER_FROM,
    assert_never,
    branch_returns_before_balance_write,
    branch_reverts_before_write,
    callee_of,
    depends,
    false_son,
    fn_ir,
    function_sort_key,
    if_nodes_on_paths,
    is_address_var,
    is_addr_bool_mapping,
    is_bool_type,
    is_ctor,
    is_externally_callable,
    is_if_node,
    is_modifier,
    is_msg_sender,
    is_numeric_type,
    is_this_expr,
    is_time_var,
    is_uint_type,
    iter_external_calls,
    iter_internal_callees,
    node_sort_key,
    require_kind,
    resolve_state_dest,
    root_state,
    solidity_sig,
    sorted_vars,
    true_son,
    unique_functions,
    values_feeding_condition,
    var_sort_key,
)
from detector.analysis.balances import Bindings, bind, balance_writes
from detector.analysis.privilege import is_privileged
from detector.analysis.roles import privileged_blocking_writable

EndKind = Literal["require", "assert", "if_revert", "if_return_before_write"]
GateShape = Literal[
    "map_addr_bool",
    "bool",
    "numeric_vs_amount",
    "numeric_vs_time",
    "address_vs_to",
    "address_vs_from",
]
GateKeySource = Literal["from", "to", "msg.sender", "other"] | None

_CMP = (
    BinaryType.LESS,
    BinaryType.GREATER,
    BinaryType.LESS_EQUAL,
    BinaryType.GREATER_EQUAL,
    BinaryType.EQUAL,
    BinaryType.NOT_EQUAL,
)


@dataclass
class EndNode:
    node: Node
    kind: EndKind
    guard_conditions: list[Node] = field(default_factory=list)


@dataclass(frozen=True)
class GateRead:
    end_node: EndNode
    var: StateVariable
    shape: GateShape
    key_source: GateKeySource


def _implemented_sig(contract: Any, signature: str) -> list[Function]:
    found: list[Function] = []
    for fn in unique_functions(contract):
        if solidity_sig(fn) != signature:
            continue
        if not is_externally_callable(fn):
            continue
        if fn.is_implemented is False:
            continue
        if getattr(fn, "is_empty", False):
            continue
        found.append(fn)
    preferred = [fn for fn in found if not fn.is_shadowed and fn.is_implemented]
    return preferred or [fn for fn in found if fn.is_implemented] or found


def transfer_roots(contract: Any, ctx: Any | None = None) -> list[Function]:
    roots = _implemented_sig(contract, SIG_TRANSFER) + _implemented_sig(contract, SIG_TRANSFER_FROM)
    # Keep order deterministic; drop duplicates.
    seen: set[int] = set()
    ordered: list[Function] = []
    for fn in roots:
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        ordered.append(fn)
    if ordered:
        return ordered
    bindings = ctx.bindings if ctx is not None else bind(contract)
    if not bindings.balance_vars:
        return []
    fallback: list[Function] = []
    for fn in unique_functions(contract):
        if is_ctor(fn) or is_modifier(fn) or not is_externally_callable(fn):
            continue
        if is_privileged(fn):
            continue
        writes = balance_writes(fn, bindings)
        has_sender_debit = any(w.kind == "debit" and w.key_source == "msg.sender" for w in writes)
        has_other_credit = any(w.kind == "credit" and w.key_source != "msg.sender" for w in writes)
        if has_sender_debit and has_other_credit:
            fallback.append(fn)
    return fallback


def transfer_path(contract: Any, ctx: Any | None = None) -> set[Function]:
    roots = transfer_roots(contract, ctx)
    path: set[Function] = set()
    stack = list(roots)
    while stack:
        fn = stack.pop()
        if fn in path or fn is None:
            continue
        path.add(fn)
        for mod in fn.modifiers:
            if isinstance(mod, Function) and mod not in path:
                stack.append(mod)
        for _, callee in iter_internal_callees(fn):
            if callee not in path and not is_ctor(callee):
                stack.append(callee)
    return path


def amount_params(root: Function) -> list[Variable]:
    params = [p for p in root.parameters if is_uint_type(p.type)]
    sig = solidity_sig(root)
    if sig == SIG_TRANSFER_FROM and len(root.parameters) >= 3:
        third = root.parameters[2]
        if is_uint_type(third.type):
            return [third]
    return params


def _seed_roles(root: Function) -> dict[Variable, str]:
    roles: dict[Variable, str] = {}
    sig = solidity_sig(root)
    addrs = [p for p in root.parameters if is_address_var(p)]
    uints = amount_params(root)
    if sig == SIG_TRANSFER:
        if addrs:
            roles[addrs[0]] = "to"
        for u in uints:
            roles[u] = "amount"
    elif sig == SIG_TRANSFER_FROM:
        if len(addrs) >= 1:
            roles[addrs[0]] = "from"
        if len(addrs) >= 2:
            roles[addrs[1]] = "to"
        for u in uints:
            roles[u] = "amount"
    else:
        if len(addrs) >= 2:
            roles[addrs[0]] = "from"
            roles[addrs[1]] = "to"
        elif len(addrs) == 1:
            roles[addrs[0]] = "to"
        for u in uints:
            roles[u] = "amount"
    return roles


def _propagate_roles(path: set[Function], roots: list[Function]) -> dict[int, dict[Variable, str]]:
    roles_by_fn: dict[int, dict[Variable, str]] = {id(r): _seed_roles(r) for r in roots}
    stack = list(roots)
    seen: set[int] = set()
    while stack:
        fn = stack.pop()
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        mine = roles_by_fn.setdefault(id(fn), {})
        for ir, callee in iter_internal_callees(fn):
            if callee not in path:
                continue
            callee_roles = roles_by_fn.setdefault(id(callee), {})
            args = list(ir.arguments or [])
            params = list(callee.parameters or [])
            helper = fn_ir(fn)
            for idx, param in enumerate(params):
                if idx >= len(args):
                    break
                arg = args[idx]
                if is_msg_sender(arg) or is_msg_sender(helper.unwrap(arg)):
                    if is_modifier(callee):
                        callee_roles.setdefault(param, "msg.sender")
                    elif is_address_var(param):
                        callee_roles.setdefault(param, "from")
                    continue
                ordered_roles = sorted(mine.items(), key=lambda item: var_sort_key(item[0]))
                assigned = False
                for src, role in ordered_roles:
                    if arg is src or helper.unwrap(arg) is src:
                        callee_roles.setdefault(param, role)
                        assigned = True
                        break
                if not assigned:
                    for src, role in ordered_roles:
                        if depends(arg, src, fn):
                            callee_roles.setdefault(param, role)
                            break
            stack.append(callee)
        for stmt in getattr(fn, "modifiers_statements", []) or []:
            for node in stmt.nodes:
                for ir in node.irs:
                    if not isinstance(ir, (InternalCall, LibraryCall)):
                        continue
                    callee = callee_of(ir)
                    if callee is None or callee not in path:
                        continue
                    callee_roles = roles_by_fn.setdefault(id(callee), {})
                    args = list(ir.arguments or [])
                    params = list(callee.parameters or [])
                    helper = fn_ir(fn)
                    for idx, param in enumerate(params):
                        if idx >= len(args):
                            break
                        arg = args[idx]
                        if is_msg_sender(arg) or is_msg_sender(helper.unwrap(arg)):
                            callee_roles.setdefault(param, "msg.sender")
                            continue
                        ordered_roles = sorted(mine.items(), key=lambda item: var_sort_key(item[0]))
                        assigned = False
                        for src, role in ordered_roles:
                            if arg is src or helper.unwrap(arg) is src:
                                callee_roles.setdefault(param, role)
                                assigned = True
                                break
                        if not assigned:
                            for src, role in ordered_roles:
                                if depends(arg, src, fn):
                                    callee_roles.setdefault(param, role)
                                    break
                    stack.append(callee)
        for mod in fn.modifiers:
            if isinstance(mod, Function) and mod in path:
                stack.append(mod)
    return roles_by_fn


def _amount_vars(path: set[Function], roots: list[Function]) -> dict[int, set[Variable]]:
    amounts: dict[int, set[Variable]] = {id(r): set(amount_params(r)) for r in roots}
    stack = list(roots)
    seen: set[int] = set()
    while stack:
        fn = stack.pop()
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        mine = amounts.setdefault(id(fn), set())
        for ir, callee in iter_internal_callees(fn):
            if callee not in path:
                continue
            dest = amounts.setdefault(id(callee), set())
            args = list(ir.arguments or [])
            params = list(callee.parameters or [])
            for idx, param in enumerate(params):
                if idx >= len(args):
                    break
                arg = args[idx]
                if arg in mine or any(depends(arg, src, fn) for src in mine):
                    dest.add(param)
            stack.append(callee)
    return amounts


def is_amount_dependent(var: Variable, function: Function, ctx: Any) -> bool:
    meta = _path_meta(ctx)
    mine = meta.amounts.get(id(function), set())
    if var in mine:
        return True
    for src in mine:
        if depends(var, src, function):
            return True
    helper = fn_ir(function)
    unwrapped = helper.unwrap(var)
    if unwrapped in mine:
        ir = helper.def_of(var)
        if isinstance(ir, Binary):
            return True
        return True
    return False


@dataclass
class _PathMeta:
    roots: list[Function]
    path: set[Function]
    roles: dict[int, dict[Variable, str]]
    amounts: dict[int, set[Variable]]


def _path_meta(ctx: Any) -> _PathMeta:
    cached = getattr(ctx, "_path_meta_cache", None)
    if cached is not None:
        return cached
    contract = ctx.contract
    roots = transfer_roots(contract, ctx)
    path = transfer_path(contract, ctx)
    roles = _propagate_roles(path, roots)
    amounts = _amount_vars(path, roots)
    meta = _PathMeta(roots=roots, path=path, roles=roles, amounts=amounts)
    setattr(ctx, "_path_meta_cache", meta)
    return meta


def _end_kind(node: Node, bindings: Bindings) -> EndKind | None:
    rk = require_kind(node)
    if rk == "require":
        return "require"
    if rk == "assert":
        return "assert"
    if rk is not None:
        assert_never(rk)
    if is_if_node(node):
        if branch_reverts_before_write(true_son(node)) or branch_reverts_before_write(false_son(node)):
            return "if_revert"
        if bindings.balance_vars and (
            branch_returns_before_balance_write(true_son(node), bindings.balance_vars)
            or branch_returns_before_balance_write(false_son(node), bindings.balance_vars)
        ):
            return "if_return_before_write"
    return None


def _guards_for(node: Node, function: Function) -> list[Node]:
    entry = function.entry_point
    return if_nodes_on_paths(node, entry)


def end_nodes(contract: Any, ctx: Any | None = None) -> list[EndNode]:
    if ctx is None:
        path = transfer_path(contract)
        bindings = bind(contract)
    else:
        path = ctx.transfer_path
        bindings = ctx.bindings
    out: list[EndNode] = []
    seen: set[int] = set()
    for fn in sorted(path, key=function_sort_key):
        if is_ctor(fn):
            continue
        for node in fn.nodes:
            kind = _end_kind(node, bindings)
            if kind is None:
                continue
            if id(node) in seen:
                continue
            seen.add(id(node))
            if kind not in ("require", "assert", "if_revert", "if_return_before_write"):
                assert_never(kind)
            out.append(EndNode(node=node, kind=kind, guard_conditions=_guards_for(node, fn)))
    return out


def _param_role(var: Any, function: Function, roles: dict[Variable, str]) -> str | None:
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if var in roles:
        return roles[var]
    if cur in roles:
        return roles[cur]
    for param, role in sorted(roles.items(), key=lambda item: var_sort_key(item[0])):
        if depends(var, param, function) or depends(cur, param, function):
            return role
    if is_msg_sender(cur) or is_msg_sender(var):
        return "msg.sender"
    return None


def _as_key_source(role: str | None, key: Any, function: Function) -> GateKeySource:
    helper = fn_ir(function)
    if role in ("from", "to"):
        return role  # type: ignore[return-value]
    if role == "msg.sender" or is_msg_sender(key) or is_msg_sender(helper.unwrap(key)):
        return "msg.sender"
    return "other"


def _invocation_roles(param: Variable, function: Function, ctx: Any) -> set[str]:
    meta = _path_meta(ctx)
    found: set[str] = set()
    callers = list(meta.path)
    for caller in callers:
        caller_roles = meta.roles.get(id(caller), {})
        sites: list[Any] = []
        for ir, callee in iter_internal_callees(caller):
            if callee is function:
                sites.append(ir)
        for stmt in getattr(caller, "modifiers_statements", []) or []:
            for node in stmt.nodes:
                for ir in node.irs:
                    if isinstance(ir, (InternalCall, LibraryCall)) and callee_of(ir) is function:
                        sites.append(ir)
        helper = fn_ir(caller)
        for ir in sites:
            args = list(ir.arguments or [])
            params = list(function.parameters or [])
            for idx, item in enumerate(params):
                if item is not param or idx >= len(args):
                    continue
                arg = args[idx]
                role = _param_role(arg, caller, caller_roles)
                if role:
                    found.add(role)
                if is_msg_sender(arg) or is_msg_sender(helper.unwrap(arg)):
                    found.add("msg.sender")
    return found


def _shape_for(
    end: EndNode,
    var: StateVariable,
    function: Function,
    ctx: Any,
    roles: dict[Variable, str],
) -> list[tuple[GateShape, GateKeySource]]:
    node = end.node
    results: list[tuple[GateShape, GateKeySource]] = []
    helper = fn_ir(function)

    indexes: list[tuple[Any, Any]] = []
    compares: list[Binary] = []
    for ir in node.irs:
        if isinstance(ir, Index) and root_state(ir.lvalue, function) is var:
            indexes.append((ir.lvalue, ir.variable_right))
        if isinstance(ir, Binary) and ir.type in _CMP:
            compares.append(ir)

    if is_addr_bool_mapping(var) or (isinstance(var.type, type(var.type)) and is_addr_bool_mapping(var)):
        keys = [key for _, key in indexes]
        if not keys:
            for ir in node.irs:
                if not isinstance(ir, (InternalCall, LibraryCall)):
                    continue
                callee = callee_of(ir)
                if callee is None:
                    continue
                reads = list(callee.state_variables_read)
                for _, inner in iter_internal_callees(callee):
                    reads.extend(inner.state_variables_read)
                if var not in reads and not any(
                    root_state(rv, callee) is var for rv in (callee.return_values or [])
                ):
                    continue
                for arg in ir.arguments or []:
                    if is_address_var(arg) or is_msg_sender(arg):
                        keys.append(arg)
            if not keys:
                keys.extend(p for p in function.parameters if is_address_var(p))
        for key in keys:
            roles_found: set[str] = set()
            local = _param_role(key, function, roles)
            if local:
                roles_found.add(local)
            if key in function.parameters:
                roles_found |= _invocation_roles(key, function, ctx)
            if is_msg_sender(key) or is_msg_sender(helper.unwrap(key)):
                roles_found.add("msg.sender")
            if not roles_found:
                roles_found.add("other")
            for role in sorted(roles_found):
                results.append(("map_addr_bool", _as_key_source(role, key, function)))

    if is_bool_type(var.type) and not is_addr_bool_mapping(var):
        results.append(("bool", None))

    for cmp in compares:
        left, right = cmp.variable_left, cmp.variable_right
        sides = ((left, right), (right, left))
        for a, b in sides:
            a_root = root_state(a, function)
            b_root = root_state(b, function)
            a_is_var = a is var or a_root is var or depends(a, var, function)
            b_is_var = b is var or b_root is var or depends(b, var, function)
            if not (a_is_var or b_is_var):
                continue
            other = b if a_is_var else a
            if is_numeric_type(var.type) or is_uint_type(var.type):
                if is_amount_dependent(other, function, ctx) or (
                    other in roles and roles.get(other) == "amount"
                ) or (helper.unwrap(other) in roles and roles.get(helper.unwrap(other)) == "amount"):
                    results.append(("numeric_vs_amount", None))
                if is_time_var(other) or is_time_var(helper.unwrap(other)):
                    results.append(("numeric_vs_time", None))
            if is_address_var(var):
                role = _param_role(other, function, roles)
                if role == "to":
                    results.append(("address_vs_to", None))
                elif role == "from":
                    results.append(("address_vs_from", None))
    # Dedup while keeping order
    seen: set[tuple[str, str | None]] = set()
    unique: list[tuple[GateShape, GateKeySource]] = []
    for shape, ks in results:
        key = (shape, ks)
        if key in seen:
            continue
        seen.add(key)
        if shape not in (
            "map_addr_bool",
            "bool",
            "numeric_vs_amount",
            "numeric_vs_time",
            "address_vs_to",
            "address_vs_from",
        ):
            assert_never(shape)
        unique.append((shape, ks))
    return unique


def _state_in_condition(node: Node, function: Function) -> list[StateVariable]:
    found: list[StateVariable] = []
    seen: set[int] = set()

    def add(sv: StateVariable | None) -> None:
        if sv is None or id(sv) in seen:
            return
        seen.add(id(sv))
        found.append(sv)

    for sv in sorted_vars(node.state_variables_read):
        add(sv)
    for val in values_feeding_condition(node):
        add(root_state(val, function))
        if isinstance(val, StateVariable):
            add(val)
    for ir in node.irs:
        if isinstance(ir, (InternalCall, LibraryCall)):
            callee = callee_of(ir)
            if callee is None:
                continue
            for sv in sorted_vars(callee.state_variables_read):
                add(sv)
            for rv in callee.return_values or []:
                add(root_state(rv, callee))
                if isinstance(rv, StateVariable):
                    add(rv)
            # Recurse one more view layer (paused() → _paused, owner() → _owner).
            for _, inner in iter_internal_callees(callee):
                if inner.view or inner.pure:
                    for sv in sorted_vars(inner.state_variables_read):
                        add(sv)
    return found


def gate_reads(ctx: Any) -> list[GateRead]:
    meta = _path_meta(ctx)
    out: list[GateRead] = []
    for end in ctx.end_nodes:
        node = end.node
        function = node.function
        roles = meta.roles.get(id(function), {})
        for var in _state_in_condition(node, function):
            if not privileged_blocking_writable(ctx, var, end):
                continue
            for shape, key_source in _shape_for(end, var, function, ctx, roles):
                out.append(GateRead(end, var, shape, key_source))
    out.sort(
        key=lambda g: (
            var_sort_key(g.var),
            g.shape,
            g.key_source or "",
            node_sort_key(g.end_node.node),
        )
    )
    return out


def external_calls_on_path(ctx: Any) -> list[tuple[Function, Node, StateVariable | None]]:
    out: list[tuple[Function, Node, StateVariable | None]] = []
    for fn in sorted(ctx.transfer_path, key=function_sort_key):
        if is_ctor(fn):
            continue
        for node in fn.nodes:
            for ir in iter_external_calls(node):
                dest = getattr(ir, "destination", None)
                target = resolve_state_dest(dest, fn)
                if target is None and dest is not None and not is_this_expr(dest, fn):
                    # CONVERT state → interface lives in the same node.
                    helper = fn_ir(fn)
                    conv = helper.def_of(dest)
                    if conv is not None:
                        target = resolve_state_dest(getattr(conv, "variable", dest), fn)
                out.append((fn, node, target))
    return out
