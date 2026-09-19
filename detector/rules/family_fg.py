"""Family F/G: approval drainers, legacy honeypots, and ponzi payout shape."""

from __future__ import annotations

from typing import Any

from slither.core.declarations.function import Function
from slither.core.solidity_types.array_type import ArrayType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, HighLevelCall, Index, LibraryCall, LowLevelCall
from slither.slithir.operations.binary import BinaryType

from detector.analysis._ir import (
    MSG_SENDER,
    MSG_VALUE,
    SIG_TRANSFER,
    SIG_TRANSFER_FROM,
    assert_never,
    branch_reverts_before_write,
    call_full_name,
    depends,
    false_son,
    fn_ir,
    index_chain,
    is_ctor,
    is_externally_callable,
    is_if_node,
    is_modifier,
    is_msg_sender,
    is_msg_value,
    is_require_assert_node,
    is_whole_pot_value,
    resolve_state_dest,
    root_state,
    true_son,
    unique_functions,
    values_feeding_condition,
)
from detector.analysis.context import ContractContext
from detector.analysis.flows import is_whole_pot, token_out_calls, value_sends
from detector.analysis.privilege import is_privileged
from detector.model import Finding
from detector.rules.base import make_finding

_PULL_SIGS = frozenset(
    {
        SIG_TRANSFER_FROM,
        "safeTransferFrom(address,address,uint256)",
        "safeTransferFrom(address,address,uint256,bytes)",
    }
)
_PULL_NAMES = frozenset({"transferFrom", "safeTransferFrom"})


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


def _sender_dependent(var: Any, function: Function) -> bool:
    if var is None:
        return False
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if is_msg_sender(var) or is_msg_sender(cur):
        return True
    return depends(var, MSG_SENDER, function) or depends(cur, MSG_SENDER, function)


def _is_pull_call(ir: Any) -> bool:
    if isinstance(ir, LibraryCall) or not isinstance(ir, HighLevelCall):
        return False
    full = call_full_name(ir)
    name = str(ir.function_name) if ir.function_name is not None else ""
    if full in _PULL_SIGS:
        return True
    if name in _PULL_NAMES and len(list(ir.arguments or [])) >= 3:
        return True
    return False


def _is_permit_call(ir: Any) -> bool:
    if isinstance(ir, LibraryCall) or not isinstance(ir, HighLevelCall):
        return False
    name = str(ir.function_name) if ir.function_name is not None else ""
    full = call_full_name(ir)
    return name == "permit" or full.startswith("permit(")


def _sender_keyed_write(function: Function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            lval = getattr(ir, "lvalue", None)
            if lval is None:
                continue
            _root, keys = index_chain(lval, function)
            for key in keys:
                if _sender_dependent(key, function):
                    return True
    return False


def _sends_to_sender(function: Function, ctx: ContractContext) -> bool:
    for _node, to_expr, _value, kind in value_sends(function):
        if kind == "selfdestruct":
            continue
        if kind not in ("transfer", "send", "call_value"):
            assert_never(kind)
        if _sender_dependent(to_expr, function):
            return True
    for _node, _call, _source, to_expr, _amount in token_out_calls(function, ctx.bindings):
        if _sender_dependent(to_expr, function):
            return True
    return False


def drain_approval_pull(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        if not is_externally_callable(function) or not function.is_implemented:
            continue
        if is_privileged(function):
            continue
        pulls: list[tuple[Any, Any]] = []
        permit_nodes: list[Any] = []
        for node in function.nodes:
            for ir in node.irs:
                if _is_permit_call(ir):
                    permit_nodes.append(node)
                if not _is_pull_call(ir):
                    continue
                args = list(ir.arguments or [])
                if len(args) < 2:
                    continue
                if not _sender_dependent(args[0], function):
                    continue
                if _sender_dependent(args[1], function):
                    continue
                pulls.append((node, ir))
        if not pulls:
            continue
        if _sender_keyed_write(function) or _sends_to_sender(function, ctx):
            continue
        if function.name in seen:
            continue
        seen.add(function.name)
        node, _ir = pulls[0]
        suffix = " after permit" if permit_nodes else ""
        findings.append(
            _emit(
                "DRAIN_APPROVAL_PULL",
                ctx,
                function,
                node,
                f"{function.name} pulls tokens from the caller to a non-caller with no sender-keyed credit{suffix}",
            )
        )
    return findings


def _non_ctor_writers(ctx: ContractContext, var: StateVariable) -> list[Function]:
    found: list[Function] = []
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        if var in function.state_variables_written or var in function.all_state_variables_written():
            found.append(function)
    return found


def _ctor_or_priv_only(ctx: ContractContext, var: StateVariable) -> bool:
    return all(is_privileged(fn) for fn in _non_ctor_writers(ctx, var))


def _ctor_only(ctx: ContractContext, var: StateVariable) -> bool:
    return not _non_ctor_writers(ctx, var)


def _local_ends(function: Function) -> list[Any]:
    found: list[Any] = []
    for node in function.nodes:
        if is_require_assert_node(node):
            found.append(node)
            continue
        if is_if_node(node) and (
            branch_reverts_before_write(true_son(node)) or branch_reverts_before_write(false_son(node))
        ):
            found.append(node)
    return found


def _caller_supplied(node: Any, function: Function) -> bool:
    params = list(function.parameters or [])
    helper = fn_ir(function)
    for val in values_feeding_condition(node):
        cur = helper.unwrap(val)
        if val in params or cur in params:
            return True
        if any(depends(val, p, function) or depends(cur, p, function) for p in params):
            return True
    for ir in node.irs:
        if isinstance(ir, Index) and _sender_dependent(ir.variable_right, function):
            return True
    return False


def _is_value_side(var: Any, function: Function) -> bool:
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if is_msg_value(var) or is_msg_value(cur):
        return True
    return depends(var, MSG_VALUE, function) or depends(cur, MSG_VALUE, function)


def _is_balance_side(var: Any, function: Function) -> bool:
    return is_whole_pot_value(var, function)


def _balance_disorder(node: Any, function: Function) -> bool:
    for ir in node.irs:
        if not isinstance(ir, Binary):
            continue
        left, right = ir.variable_left, ir.variable_right
        if ir.type == BinaryType.GREATER and _is_value_side(left, function) and _is_balance_side(right, function):
            return True
        if ir.type == BinaryType.LESS and _is_balance_side(left, function) and _is_value_side(right, function):
            return True
    return False


def _secret_compare(node: Any, function: Function, ctx: ContractContext) -> bool:
    for ir in node.irs:
        if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            continue
        for side in (ir.variable_left, ir.variable_right):
            root = side if isinstance(side, StateVariable) else None
            if root is None:
                dest = resolve_state_from(side, function)
                root = dest
            if root is None:
                continue
            if _ctor_only(ctx, root):
                return True
    return any(_ctor_only(ctx, sv) for sv in node.state_variables_read)


def resolve_state_from(var: Any, function: Function) -> StateVariable | None:
    if isinstance(var, StateVariable):
        return var
    return resolve_state_dest(var, function) or root_state(var, function)


def honeypot_legacy(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        if not is_externally_callable(function) or not function.is_implemented:
            continue
        if is_privileged(function):
            continue
        sends = [(n, to, val, kind) for n, to, val, kind in value_sends(function) if kind != "selfdestruct"]
        whole = any(is_whole_pot(val, function) for _n, _to, val, _k in sends)
        ends = _local_ends(function)
        hit = False
        node = function
        if whole:
            for end in ends:
                if _caller_supplied(end, function) and any(
                    _ctor_or_priv_only(ctx, sv) for sv in end.state_variables_read
                ):
                    hit = True
                    node = end
                    break
            if not hit:
                for end in ends:
                    if _secret_compare(end, function, ctx):
                        hit = True
                        node = end
                        break
        for end in ends:
            if _balance_disorder(end, function):
                hit = True
                node = end
                break
        if not hit and whole:
            for end in ends:
                if _secret_compare(end, function, ctx) and sends:
                    hit = True
                    node = end
                    break
        if not hit:
            continue
        if function.name in seen:
            continue
        seen.add(function.name)
        findings.append(
            _emit(
                "HONEYPOT_LEGACY",
                ctx,
                function,
                node,
                f"{function.name} exits ETH under a caller-supplied or constructor-secret compare",
            )
        )
    return findings


def _is_array_or_map(var: StateVariable) -> bool:
    return isinstance(var.type, (ArrayType, MappingType))


def _written_by_payable(ctx: ContractContext, var: StateVariable) -> bool:
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        if not (function.payable or function.is_receive or function.is_fallback):
            continue
        if var in function.state_variables_written or var in function.all_state_variables_written():
            return True
    return False


def _external_value_source(ctx: ContractContext) -> bool:
    for function in unique_functions(ctx.contract):
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, LibraryCall):
                    continue
                if isinstance(ir, HighLevelCall):
                    full = call_full_name(ir)
                    name = str(ir.function_name) if ir.function_name is not None else ""
                    if full in (SIG_TRANSFER, SIG_TRANSFER_FROM) or name in ("transfer", "transferFrom"):
                        continue
                    if ir.call_value is not None:
                        continue
                    if ir.lvalue is not None:
                        return True
                elif isinstance(ir, LowLevelCall):
                    if ir.call_value is not None:
                        continue
                    if ir.lvalue is not None:
                        return True
    return False


def ponzi_shape(ctx: ContractContext) -> list[Finding]:
    if _external_value_source(ctx):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        for node, to_expr, _value, kind in value_sends(function):
            if kind == "selfdestruct":
                continue
            if kind not in ("transfer", "send", "call_value"):
                assert_never(kind)
            if _sender_dependent(to_expr, function):
                continue
            dest = resolve_state_from(to_expr, function)
            if dest is None or not _is_array_or_map(dest):
                continue
            if not _written_by_payable(ctx, dest):
                continue
            if function.name in seen:
                continue
            seen.add(function.name)
            findings.append(
                _emit(
                    "PONZI_SHAPE",
                    ctx,
                    function,
                    node,
                    f"{function.name} sends ETH to a payee loaded from {dest.name}, which a payable function populates",
                )
            )
    return findings


RULES = [drain_approval_pull, honeypot_legacy, ponzi_shape]
