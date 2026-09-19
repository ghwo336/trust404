"""Family A: privileged roles, exit gates, callback cycles, unbounded fees."""

from __future__ import annotations

from detector.analysis import balances, flows, privilege, roles
from detector.analysis._ir import (
    assert_never,
    branch_reverts_before_write,
    depends,
    false_son,
    fn_ir,
    is_ctor,
    is_if_node,
    is_modifier,
    is_numeric_type,
    is_require_assert_node,
    is_time_var,
    is_uint_type,
    iter_internal_callees,
    root_state,
    true_son,
    unique_functions,
)
from detector.analysis.context import ContractContext
from detector.model import Finding
from detector.rules.base import (
    combined_shape_discriminators,
    contract_name,
    function_name,
    make_finding,
    node_lines,
)
from slither.slithir.operations import Assignment, Binary
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables.constant import Constant

_GATE_RULE = {
    "map_addr_bool": "EXIT_ADDR_GATE",
    "bool": "EXIT_GLOBAL_SWITCH",
    "numeric_vs_amount": "EXIT_AMOUNT_LIMIT",
    "numeric_vs_time": "EXIT_TIME_GATE",
    "address_vs_to": "EXIT_SELL_ONLY",
    "address_vs_from": "EXIT_SELL_ONLY",
}

_FLOOR_CMP = (BinaryType.GREATER, BinaryType.GREATER_EQUAL)
_CEIL_CMP = (BinaryType.LESS, BinaryType.LESS_EQUAL)


def _cname(ctx: ContractContext) -> str:
    return contract_name(ctx.contract)


def _local_end_nodes(function) -> list:
    out = []
    for node in function.nodes:
        if is_require_assert_node(node):
            out.append(node)
            continue
        if is_if_node(node) and (
            branch_reverts_before_write(true_son(node))
            or branch_reverts_before_write(false_son(node))
        ):
            out.append(node)
    return out


def _closure(function) -> list:
    out = []
    stack = [function]
    seen: set[int] = set()
    while stack:
        cur = stack.pop()
        if id(cur) in seen:
            continue
        seen.add(id(cur))
        out.append(cur)
        for _, callee in iter_internal_callees(cur):
            stack.append(callee)
    return out


def _const_int(var) -> int | None:
    if isinstance(var, Constant):
        val = var.value
        if isinstance(val, bool):
            return None
        if isinstance(val, int):
            return val
        try:
            return int(val)
        except (TypeError, ValueError):
            return None
    return None


def _assigned_rvalues(function, var) -> list:
    values = []
    helper = fn_ir(function)
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            root = ir.lvalue if ir.lvalue is var else root_state(ir.lvalue, function)
            if root is not var:
                continue
            values.append(helper.unwrap(ir.rvalue))
            values.append(ir.rvalue)
    return values


def _operand_is_value(operand, values, function) -> bool:
    helper = fn_ir(function)
    cur = helper.unwrap(operand)
    for val in values:
        if operand is val or cur is val or helper.unwrap(val) is cur:
            return True
        if depends(operand, val, function) or depends(cur, val, function):
            return True
    if not values:
        for param in function.parameters:
            if operand is param or cur is param or depends(operand, param, function):
                return True
    return False


def _cmp_binaries(node) -> list[Binary]:
    return [ir for ir in node.irs if isinstance(ir, Binary) and ir.type in _FLOOR_CMP + _CEIL_CMP]


def _writer_has_floor(ctx: ContractContext, function, var) -> bool:
    values = _assigned_rvalues(function, var)
    for site in _closure(function):
        site_values = values + _assigned_rvalues(site, var)
        for node in _local_end_nodes(site):
            if not balances.is_constant_bound(node, ctx):
                continue
            for ir in _cmp_binaries(node):
                left, right = ir.variable_left, ir.variable_right
                if ir.type in _FLOOR_CMP and _operand_is_value(left, site_values, site):
                    return True
                if ir.type in _CEIL_CMP and _operand_is_value(right, site_values, site):
                    return True
    return False


def _constant_floor(ctx: ContractContext, var) -> bool:
    writers = _writer_fns(ctx, var)
    if not writers:
        return False
    return all(_writer_has_floor(ctx, fn, var) for fn in writers)


def _is_time_plus_const(var, function) -> bool:
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    ir = helper.def_of(var) or helper.def_of(cur)
    if isinstance(ir, Binary) and ir.type == BinaryType.ADDITION:
        sides = (ir.variable_left, ir.variable_right)
        time_side = any(is_time_var(side) or is_time_var(helper.unwrap(side)) for side in sides)
        const_side = any(_const_int(side) is not None for side in sides)
        return time_side and const_side
    return False


def _writer_has_upper_expiry(function, var) -> bool:
    values = _assigned_rvalues(function, var)
    for site in _closure(function):
        site_values = values + _assigned_rvalues(site, var)
        for node in _local_end_nodes(site):
            for ir in _cmp_binaries(node):
                left, right = ir.variable_left, ir.variable_right
                if ir.type in _CEIL_CMP and _operand_is_value(left, site_values, site):
                    bound = right
                elif ir.type in _FLOOR_CMP and _operand_is_value(right, site_values, site):
                    bound = left
                else:
                    continue
                helper = fn_ir(site)
                if _const_int(bound) is not None or _const_int(helper.unwrap(bound)) is not None:
                    return True
                if _is_time_plus_const(bound, site):
                    return True
                if is_time_var(bound) or is_time_var(helper.unwrap(bound)):
                    return True
    return False


def _no_expiry(ctx: ContractContext, var) -> bool:
    writers = _writer_fns(ctx, var)
    if not writers:
        return True
    return not any(_writer_has_upper_expiry(fn, var) for fn in writers)


def _guard_is_bounded_window(ctx: ContractContext, end) -> bool:
    for guard in end.guard_conditions:
        feeds = []
        helper = fn_ir(guard.function)
        for ir in guard.irs:
            if isinstance(ir, Binary):
                feeds.extend([ir.variable_left, ir.variable_right])
        has_time = any(is_time_var(v) or is_time_var(helper.unwrap(v)) for v in feeds)
        if not has_time:
            continue
        if any(sv in ctx.privileged_writable for sv in guard.state_variables_read):
            continue
        if balances.is_constant_bound(guard, ctx):
            return True
    return False


def _writer_fns(ctx: ContractContext, var) -> list:
    seen: set[int] = set()
    out = []
    for pw in ctx.privileged_writable.get(var, []):
        if pw.mode != "function":
            continue
        fn = pw.function
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        out.append(fn)
    return out


def _writer_nodes(ctx: ContractContext, var) -> list:
    seen: set[tuple[int, int]] = set()
    out = []
    for pw in ctx.privileged_writable.get(var, []):
        if pw.mode != "function":
            continue
        key = (id(pw.function), id(pw.node))
        if key in seen:
            continue
        seen.add(key)
        out.append(pw)
    return out


def _append_unique(into: list[Finding], finding: Finding) -> None:
    key = (finding.rule_id, finding.function, finding.lines, finding.severity)
    if any((item.rule_id, item.function, item.lines, item.severity) == key for item in into):
        return
    into.append(finding)


def _gate_rules(ctx: ContractContext) -> list[Finding]:
    cached = getattr(ctx, "_family_a_gate_findings", None)
    if cached is not None:
        return cached
    out: list[Finding] = []
    seen_pairs: set[tuple[str, int, int]] = set()
    for gate in ctx.gate_reads:
        shape = gate.shape
        if shape not in _GATE_RULE:
            assert_never(shape)
        rule_id = _GATE_RULE[shape]
        if shape == "map_addr_bool" and gate.key_source not in ("from", "to", "msg.sender"):
            continue
        pair = (rule_id, id(gate.var), id(gate.end_node.node))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        extra: list[str] = []
        if rule_id == "EXIT_GLOBAL_SWITCH":
            if roles.ungate_exists(ctx, gate.var, gate.end_node):
                extra.append("ungate_exists")
        elif rule_id == "EXIT_AMOUNT_LIMIT":
            if _constant_floor(ctx, gate.var):
                extra.append("constant_floor")
            if _guard_is_bounded_window(ctx, gate.end_node):
                extra.append("bounded_window")
        elif rule_id == "EXIT_TIME_GATE":
            if _no_expiry(ctx, gate.var):
                extra.append("no_expiry")
        writers = _writer_fns(ctx, gate.var)
        discs = tuple(extra) + combined_shape_discriminators(ctx, writers)
        severity = None
        if rule_id == "EXIT_TIME_GATE" and "no_expiry" in extra:
            severity = "HIGH"
            discs = ("no_expiry",) + tuple(d for d in discs if d != "no_expiry")
        kind = gate.end_node.kind
        impact = gate.end_node.node.function
        reasoning = (
            f"{function_name(writers[0]) if writers else '?'} writes {gate.var.name}; "
            f"impact {function_name(impact)} {kind}"
        )
        for pw in _writer_nodes(ctx, gate.var):
            wdiscs = tuple(extra) + combined_shape_discriminators(ctx, [pw.function])
            if "issuer_token" in discs and "issuer_token" not in wdiscs:
                wdiscs = wdiscs + ("issuer_token",)
            if rule_id == "EXIT_TIME_GATE" and "no_expiry" in extra:
                wdiscs = ("no_expiry",) + tuple(d for d in wdiscs if d != "no_expiry")
            _append_unique(
                out,
                make_finding(
                    rule_id,
                    contract=_cname(ctx),
                    function=function_name(pw.function),
                    lines=node_lines(pw.node),
                    reasoning=reasoning,
                    discriminators=wdiscs,
                    severity=severity,
                ),
            )
        _append_unique(
            out,
            make_finding(
                rule_id,
                contract=_cname(ctx),
                function=function_name(impact),
                lines=node_lines(gate.end_node.node),
                reasoning=reasoning,
                discriminators=discs,
                severity=severity,
            ),
        )
    setattr(ctx, "_family_a_gate_findings", out)
    return out


def PRIV_ROLE(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    for fn in unique_functions(ctx.contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if not ctx.is_from_input_root(fn):
            continue
        if not privilege.is_privileged(fn):
            continue
        atoms = privilege.auth_atoms(fn)
        if not atoms:
            continue
        names = ", ".join(f"{atom.auth_var.name} ({atom.kind})" for atom in atoms)
        _append_unique(
            out,
            make_finding(
                "PRIV_ROLE",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(atoms[0].node),
                reasoning=f"{function_name(fn)} gated by {names}",
            ),
        )
    return out


def EXIT_ADDR_GATE(ctx: ContractContext) -> list[Finding]:
    return [f for f in _gate_rules(ctx) if f.rule_id == "EXIT_ADDR_GATE"]


def EXIT_GLOBAL_SWITCH(ctx: ContractContext) -> list[Finding]:
    return [f for f in _gate_rules(ctx) if f.rule_id == "EXIT_GLOBAL_SWITCH"]


def EXIT_AMOUNT_LIMIT(ctx: ContractContext) -> list[Finding]:
    return [f for f in _gate_rules(ctx) if f.rule_id == "EXIT_AMOUNT_LIMIT"]


def EXIT_TIME_GATE(ctx: ContractContext) -> list[Finding]:
    return [f for f in _gate_rules(ctx) if f.rule_id == "EXIT_TIME_GATE"]


def EXIT_SELL_ONLY(ctx: ContractContext) -> list[Finding]:
    return [f for f in _gate_rules(ctx) if f.rule_id == "EXIT_SELL_ONLY"]


def EXIT_CALLBACK_CYCLE(ctx: ContractContext) -> list[Finding]:
    pw = ctx.privileged_writable
    has_pw_call = False
    for _fn, _node, target in ctx.external_calls_on_path:
        if target is not None and target in pw:
            has_pw_call = True
            break
    if not has_pw_call:
        return []
    impact = None
    writers: list = []
    for gate in ctx.gate_reads:
        if gate.shape == "numeric_vs_amount":
            impact = gate.end_node
            writers.extend(_writer_fns(ctx, gate.var))
            break
    if impact is None:
        return []
    fn = impact.node.function
    return [
        make_finding(
            "EXIT_CALLBACK_CYCLE",
            contract=_cname(ctx),
            function=function_name(fn),
            lines=node_lines(impact.node),
            reasoning=(
                f"path {function_name(fn)} calls a privileged-writable target then "
                f"compares amount at {impact.kind}"
            ),
            discriminators=combined_shape_discriminators(ctx, writers),
        )
    ]


def _depends_on_var(value, var, function) -> bool:
    if value is None:
        return False
    if value is var or root_state(value, function) is var:
        return True
    return bool(depends(value, var, function))


def _fee_denom(ctx: ContractContext, var) -> int:
    for fn in ctx.transfer_path:
        helper = fn_ir(fn)
        for node in fn.nodes:
            for ir in node.irs:
                if not isinstance(ir, Binary) or ir.type != BinaryType.DIVISION:
                    continue
                left, right = ir.variable_left, ir.variable_right
                if _depends_on_var(left, var, fn):
                    n = _const_int(right) or _const_int(helper.unwrap(right))
                    if n is not None and n > 0:
                        return n
                if _depends_on_var(right, var, fn):
                    n = _const_int(left) or _const_int(helper.unwrap(left))
                    if n is not None and n > 0:
                        return n
    return 100


def _writer_upper_constant(function, var) -> int | None:
    values = _assigned_rvalues(function, var)
    best: int | None = None
    for site in _closure(function):
        site_values = values + _assigned_rvalues(site, var)
        for node in _local_end_nodes(site):
            for ir in _cmp_binaries(node):
                left, right = ir.variable_left, ir.variable_right
                if ir.type in _CEIL_CMP and _operand_is_value(left, site_values, site):
                    bound = right
                elif ir.type in _FLOOR_CMP and _operand_is_value(right, site_values, site):
                    bound = left
                else:
                    continue
                helper = fn_ir(site)
                n = _const_int(bound) or _const_int(helper.unwrap(bound))
                if n is None:
                    continue
                best = n if best is None else max(best, n)
    return best


def _fee_cap(ctx: ContractContext, var) -> bool:
    writers = _writer_fns(ctx, var)
    if not writers:
        return False
    caps = []
    for fn in writers:
        cap = _writer_upper_constant(fn, var)
        if cap is None:
            return False
        caps.append(cap)
    denom = _fee_denom(ctx, var)
    if denom <= 0:
        denom = 100
    return max(caps) / denom <= 0.25


def _fee_impacts(ctx: ContractContext, var) -> list[tuple]:
    from detector.analysis.transfer_path import _path_meta

    meta = _path_meta(ctx)
    hits: list[tuple] = []
    for fn in ctx.transfer_path:
        if is_ctor(fn):
            continue
        roles_map = meta.roles.get(id(fn), {})
        for write in balances.balance_writes(fn, ctx.bindings, param_roles=roles_map or None):
            if write.kind not in ("debit", "credit"):
                continue
            if _depends_on_var(write.value, var, fn):
                hits.append((fn, write.node))
        for node, _to, value, _kind in flows.value_sends(fn):
            if _depends_on_var(value, var, fn):
                hits.append((fn, node))
        for node, _call, _src, _to, amount in flows.token_out_calls(fn, ctx.bindings):
            if _depends_on_var(amount, var, fn):
                hits.append((fn, node))
    return hits


def FEE_UNBOUNDED(ctx: ContractContext) -> list[Finding]:
    gate_vars = {id(g.var) for g in ctx.gate_reads}
    out: list[Finding] = []
    for var in ctx.privileged_writable:
        if id(var) in gate_vars:
            continue
        if not (is_uint_type(var.type) or is_numeric_type(var.type)):
            continue
        impacts = _fee_impacts(ctx, var)
        if not impacts:
            continue
        extra: list[str] = []
        if _fee_cap(ctx, var):
            extra.append("fee_cap")
        writers = _writer_fns(ctx, var)
        discs = tuple(extra) + combined_shape_discriminators(ctx, writers)
        impact_fn, impact_node = impacts[0]
        reasoning = (
            f"{function_name(writers[0]) if writers else '?'} writes {var.name}; "
            f"feeds {function_name(impact_fn)} transfer amount"
        )
        for pw in _writer_nodes(ctx, var):
            wdiscs = tuple(extra) + combined_shape_discriminators(ctx, [pw.function])
            if "issuer_token" in discs and "issuer_token" not in wdiscs:
                wdiscs = wdiscs + ("issuer_token",)
            _append_unique(
                out,
                make_finding(
                    "FEE_UNBOUNDED",
                    contract=_cname(ctx),
                    function=function_name(pw.function),
                    lines=node_lines(pw.node),
                    reasoning=reasoning,
                    discriminators=wdiscs,
                ),
            )
        _append_unique(
            out,
            make_finding(
                "FEE_UNBOUNDED",
                contract=_cname(ctx),
                function=function_name(impact_fn),
                lines=node_lines(impact_node),
                reasoning=reasoning,
                discriminators=discs,
            ),
        )
    return out


RULES = [
    PRIV_ROLE,
    EXIT_ADDR_GATE,
    EXIT_GLOBAL_SWITCH,
    EXIT_AMOUNT_LIMIT,
    EXIT_TIME_GATE,
    EXIT_SELL_ONLY,
    EXIT_CALLBACK_CYCLE,
    FEE_UNBOUNDED,
]
