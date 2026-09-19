"""Family F/G: approval drainers, legacy honeypots, and ponzi payout shape."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from slither.core.cfg.node import NodeType
from slither.core.declarations.function import Function
from slither.core.solidity_types.array_type import ArrayType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, HighLevelCall, Index, LibraryCall, LowLevelCall
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables.constant import Constant

from detector.analysis._ir import (
    MSG_SENDER,
    MSG_VALUE,
    SIG_TRANSFER,
    SIG_TRANSFER_FROM,
    assert_never,
    branch_reverts_before_write,
    call_full_name,
    depends,
    elem_name,
    false_son,
    fn_ir,
    function_sort_key,
    guarded_nodes,
    guards_of_node,
    index_chain,
    is_bool_type,
    is_ctor,
    is_externally_callable,
    is_if_node,
    is_modifier,
    is_msg_sender,
    is_msg_value,
    is_require_assert_node,
    is_whole_pot_value,
    iter_internal_callees,
    pot_dependent,
    resolve_state_dest,
    root_state,
    true_son,
    unique_functions,
)
from detector.analysis.context import ContractContext
from detector.analysis.flows import state_target_calls, token_out_calls, value_sends
from detector.analysis.privilege import (
    auth_atoms,
    bait_writer_exists,
    branch_atoms,
    depositor_locked,
    is_privileged,
    shadowed_auth_vars,
)
from detector.model import Finding
from detector.rules.base import make_finding

_ORDER_TYPES = (
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
)

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
        pulls.sort(key=lambda item: _source_lines(item[0]))
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


def _send_gates(send_node: Any, function: Function) -> list[Any]:
    """Conditions deciding whether the send executes: reverting ends plus silent `if` arms."""
    gates = list(guards_of_node(send_node, function))
    seen = {id(node) for node in gates}
    for end in _local_ends(function):
        if id(end) not in seen:
            gates.append(end)
            seen.add(id(end))
    return gates


def _is_value_side(var: Any, function: Function) -> bool:
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if is_msg_value(var) or is_msg_value(cur):
        return True
    return depends(var, MSG_VALUE, function) or depends(cur, MSG_VALUE, function)


def _is_balance_side(var: Any, function: Function) -> bool:
    return is_whole_pot_value(var, function)


def _balance_disorder(node: Any, function: Function) -> bool:
    """`msg.value > address(this).balance` (or `>=`): the balance already includes
    `msg.value`, so the branch never (`>`) or only on an empty pot (`>=`) executes."""
    for ir in node.irs:
        if not isinstance(ir, Binary):
            continue
        left, right = ir.variable_left, ir.variable_right
        if ir.type in (BinaryType.GREATER, BinaryType.GREATER_EQUAL):
            if _is_value_side(left, function) and _is_balance_side(right, function):
                return True
        if ir.type in (BinaryType.LESS, BinaryType.LESS_EQUAL):
            if _is_balance_side(left, function) and _is_value_side(right, function):
                return True
    return False


def _secret_compare(node: Any, function: Function, ctx: ContractContext) -> bool:
    """An equality compare against a state var written only at construction (the secret);
    the other operand must be a real value, not a literal (`flag == 0` is a plain check)."""
    for ir in node.irs:
        if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            continue
        for side, other in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
            if isinstance(other, Constant):
                continue
            root = side if isinstance(side, StateVariable) else resolve_state_from(side, function)
            if root is None or root.is_constant:
                continue
            if _ctor_only(ctx, root):
                return True
    return False


def resolve_state_from(var: Any, function: Function) -> StateVariable | None:
    if isinstance(var, StateVariable):
        return var
    return resolve_state_dest(var, function) or root_state(var, function)


def _is_locked(var: StateVariable, ctx: ContractContext) -> bool:
    return _ctor_or_priv_only(ctx, var) or depositor_locked(ctx.contract, var)


def _operand_caller_supplied(var: Any, function: Function) -> bool:
    params = list(function.parameters or [])
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if var in params or cur in params:
        return True
    if any(depends(var, p, function) or depends(cur, p, function) for p in params):
        return True
    _root, keys = index_chain(var, function)
    return any(_sender_dependent(key, function) for key in keys)


def _priv_settable(var: StateVariable, ctx: ContractContext) -> bool:
    """Some privileged function rewrites the secret after deployment (the quiz-reset shape)."""
    return any(is_privileged(fn) for fn in _non_ctor_writers(ctx, var))


def _operand_locked_state(var: Any, function: Function, ctx: ContractContext) -> bool:
    """The compared state var is one the depositor cannot set, or one a hidden role can reset."""
    root = resolve_state_from(var, function)
    if root is not None and (_is_locked(root, ctx) or _priv_settable(root, ctx)):
        return True
    for sv in function.state_variables_read:
        if depends(var, sv, function) and (_is_locked(sv, ctx) or _priv_settable(sv, ctx)):
            return True
    return False


def _constant_key_slot(var: Any, function: Function) -> tuple[StateVariable, Constant] | None:
    """`map[<literal>]` — a single mapping slot picked by a compile-time key."""
    root, keys = index_chain(var, function)
    if root is None or len(keys) != 1 or not isinstance(keys[0], Constant):
        return None
    return root, keys[0]


def _slot_never_rewritten(root: StateVariable, key: Constant, ctx: ContractContext) -> bool:
    """Every post-constructor write to `root` indexes a *different* literal key: the slot the
    gate reads is fixed at deployment (HoneyBadger look-alike keys — `'Stephen'` vs `'Stephеn'`)."""
    for fn in _non_ctor_writers(ctx, root):
        for node in fn.nodes:
            if root not in node.state_variables_written:
                continue
            for ir in node.irs:
                if not isinstance(ir, Index) or root_state(ir.variable_left, fn) is not root:
                    continue
                written = ir.variable_right
                if not isinstance(written, Constant) or written.value == key.value:
                    return False
    return True


def _payable_writer_exists(ctx: ContractContext, root: StateVariable) -> bool:
    return any(fn.payable and not is_privileged(fn) for fn in _non_ctor_writers(ctx, root))


def _operand_baited_role(var: Any, function: Function, ctx: ContractContext) -> bool:
    """A depositor-locked state address that a payable bait writer pretends to hand out —
    either the whole var is locked, or the gate reads one literal-keyed slot no writer reaches."""
    slot = _constant_key_slot(var, function)
    if slot is not None and _slot_never_rewritten(*slot, ctx) and _payable_writer_exists(ctx, slot[0]):
        return True
    root = resolve_state_from(var, function)
    if root is None or not _is_locked(root, ctx):
        return False
    return bait_writer_exists(ctx.contract, root)


def _caller_vs_locked_compare(node: Any, function: Function, ctx: ContractContext) -> bool:
    """An equality compare in the gate between a caller-supplied operand (param, its hash,
    or a sender-keyed slot) and a depositor-locked state var (the guess-the-secret shape);
    or `msg.sender == <role>` where the role is locked but a payable bait writer offers it."""
    for ir in node.irs:
        if not isinstance(ir, Binary) or ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            continue
        for side, other in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
            if isinstance(other, Constant):
                continue
            if _operand_caller_supplied(side, function) and _operand_locked_state(other, function, ctx):
                return True
            if _sender_dependent(side, function) and _operand_baited_role(other, function, ctx):
                return True
    return False


def _prize_like(value: Any, function: Function) -> bool:
    """The payout is the pot, a `msg.value` multiple, or a plain state amount — never the
    caller's own sender-keyed deposit (the honest vault refund shape)."""
    if value is None:
        return False
    if pot_dependent(value, function) or _is_value_side(value, function):
        return True
    helper = fn_ir(function)
    cur = helper.unwrap(value)
    root, keys = index_chain(cur, function)
    if root is None:
        root = resolve_state_from(cur, function)
        keys = []
    if root is None:
        return False
    return not any(_sender_dependent(key, function) for key in keys)


def _hidden_state_gate(function: Function, sends: list, ctx: ContractContext) -> Any | None:
    for node, _to, value, _kind in sends:
        if not _prize_like(value, function):
            continue
        for gate in _send_gates(node, function):
            if _caller_vs_locked_compare(gate, function, ctx):
                return gate
    return None


def _secret_gate(function: Function, sends: list, ctx: ContractContext) -> Any | None:
    for node, _to, value, _kind in sends:
        if not _prize_like(value, function):
            continue
        for gate in _send_gates(node, function):
            if _secret_compare(gate, function, ctx):
                return gate
    return None


def _disorder_gate(function: Function, sends: list) -> Any | None:
    for node, _to, _value, _kind in sends:
        for gate in _send_gates(node, function):
            if _balance_disorder(gate, function):
                return gate
    return None


def _fixed_prize(value: Any, function: Function) -> bool:
    """A literal or pot-derived payout that is not the caller's own `msg.value` (a refund)."""
    if value is None or _is_value_side(value, function):
        return False
    return isinstance(value, Constant) or pot_dependent(value, function)


def _silent_locked_bool_gate(node: Any, send_node: Any, ctx: ContractContext) -> bool:
    """`if (... && !locked) pay()` with no revert on the skip arm, `locked` depositor-locked."""
    if not is_if_node(node) or node.type != NodeType.IF:
        return False
    skip_arm = false_son(node) if send_node in guarded_nodes(node) else true_son(node)
    if branch_reverts_before_write(skip_arm):
        return False
    for sv in node.state_variables_read:
        if not is_bool_type(sv.type) or sv.is_constant:
            continue
        if _is_locked(sv, ctx) and _non_ctor_writers(ctx, sv):
            return True
    return False


def _locked_switch_gate(function: Function, sends: list, ctx: ContractContext) -> Any | None:
    """A **payable** game entry pays the caller a fixed prize only inside a silent `if` on a
    bool the depositor can never flip but a hidden role can: when the switch is off the bet
    is still accepted and nothing is paid. A pausable refund (`if (paused) refund msg.value`)
    is not this shape — the value is the caller's own deposit."""
    if not function.payable:
        return None
    for node, to, value, _kind in sends:
        if not _sender_dependent(to, function) or not _fixed_prize(value, function):
            continue
        for gate in _send_gates(node, function):
            if _silent_locked_bool_gate(gate, node, ctx):
                return gate
    return None


def _caller_controlled(var: Any, function: Function) -> bool:
    """Destination the caller picks: `msg.sender` or an address parameter."""
    if _sender_dependent(var, function):
        return True
    params = list(function.parameters or [])
    cur = fn_ir(function).unwrap(var)
    return var in params or cur in params or any(depends(var, p, function) for p in params)


def _straw_man(function: Function, sends: list) -> Any | None:
    """ETH to a caller-chosen address next to an external call (incl. delegatecall) on a
    state-address target: the straw-man contract decides who gets paid. ERC-20 ABI calls
    and self-calls are excluded."""
    if not any(_caller_controlled(to, function) for _n, to, _v, _k in sends):
        return None
    calls = state_target_calls(function)
    return calls[0][0] if calls else None


def _uninitialised_storage(function: Function, sends: list) -> Any | None:
    """A storage-pointer local with no initializer aliases slot 0 (the secret) — 0.4 quirk."""
    if not any(_caller_controlled(to, function) for _n, to, _v, _k in sends):
        return None
    scopes = [function, *list(function.modifiers or [])]
    for scope in scopes:
        for local in scope.local_variables or []:
            if getattr(local, "is_storage", False) and getattr(local, "uninitialized", False):
                return function.entry_point
    return None


def _double_pot(function: Function, sends: list) -> Any | None:
    """Whole pot sent to a state address and then to the caller in one function: the second
    send is always empty (HoneyBadger hidden transfer — the first line is hidden by whitespace)."""
    to_state = None
    to_caller = None
    for node, to, value, _kind in sends:
        if not pot_dependent(value, function):
            continue
        if _sender_dependent(to, function):
            to_caller = node
        elif resolve_state_from(to, function) is not None:
            to_state = node
    if to_state is not None and to_caller is not None:
        return to_caller
    return None


def _narrow_loop_counter(function: Function, sends: list) -> Any | None:
    """`for (var i = 0; i < wide; i++)` — the deduced `uint8` counter wraps before the bound."""
    if not sends or not any(node.type == NodeType.IFLOOP for node in function.nodes):
        return None
    for node in function.nodes:
        # `while (true) { if (i > bound) break; ... }` puts the compare in a plain IF.
        if node.type not in (NodeType.IFLOOP, NodeType.IF):
            continue
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type not in _ORDER_TYPES:
                continue
            for side, other in ((ir.variable_left, ir.variable_right), (ir.variable_right, ir.variable_left)):
                narrow = elem_name(getattr(side, "type", None))
                wide = elem_name(getattr(other, "type", None))
                if not (narrow and wide and narrow.startswith("uint") and wide.startswith("uint")):
                    continue
                if _bits(narrow) < _bits(wide) and _bits(narrow) <= 32:
                    return node
    return None


def _bits(name: str) -> int:
    digits = name[len("uint"):]
    return int(digits) if digits else 256


def _empty_string_call(function: Function, ctx: ContractContext) -> Any | None:
    """0.4.x encoder quirk: an empty string literal among ≥2 arguments shifts the ABI."""
    version = str(getattr(getattr(ctx.contract, "compilation_unit", None), "solc_version", "") or "")
    if not version.startswith("0.4"):
        return None
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, LibraryCall) or not isinstance(ir, HighLevelCall):
                continue
            args = list(ir.arguments or [])
            if len(args) < 2:
                continue
            if any(isinstance(arg, Constant) and arg.value == "" for arg in args):
                return node
    return None


def _has_eth_exit(function: Function) -> bool:
    for site in [function] + [callee for _ir, callee in iter_internal_callees(function)]:
        if value_sends(site):
            return True
    return False


def _shadowed_role_hits(ctx: ContractContext) -> list[tuple[Function, Any, str]]:
    hits: list[tuple[Function, Any, str]] = []
    for auth, shadow in shadowed_auth_vars(ctx.contract):
        gated = [
            fn
            for fn in unique_functions(ctx.contract)
            if not is_ctor(fn)
            and not is_modifier(fn)
            and (
                any(a.auth_var is auth for a in auth_atoms(fn))
                or any(a.auth_var is auth for a, _if in branch_atoms(fn))
            )
        ]
        if not any(_has_eth_exit(fn) for fn in gated):
            continue
        gated.sort(key=function_sort_key)
        writers = sorted(_non_ctor_writers(ctx, shadow), key=function_sort_key)
        site = writers[0] if writers else gated[0]
        hits.append(
            (
                site,
                site.entry_point,
                f"{shadow.name} declared in {shadow.contract.name} shadows the {auth.contract.name} "
                f"auth var gating an ETH exit ({site.name} never reaches the real role)",
            )
        )
    return hits


def honeypot_legacy(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    contract_sends = False
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function) or not function.is_implemented:
            continue
        if value_sends(function):
            contract_sends = True
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        if not is_externally_callable(function) or not function.is_implemented:
            continue
        all_sends = value_sends(function)
        sends = [(n, to, val, kind) for n, to, val, kind in all_sends if kind != "selfdestruct"]
        node: Any = _double_pot(function, sends)
        why = "sends the whole pot to a state address and then to the caller (second send is empty)"
        if node is None and is_privileged(function):
            continue
        if node is None and all_sends:
            checks: list[tuple[Callable[[], Any], str]] = [
                (
                    lambda: _hidden_state_gate(function, sends, ctx),
                    "pays out under a caller-supplied compare against a state var the depositor cannot set",
                ),
                (
                    lambda: _disorder_gate(function, sends),
                    "compares msg.value against the contract balance in a way that cannot hold",
                ),
                (
                    lambda: _secret_gate(function, sends, ctx),
                    "pays out only when a constructor-set secret matches",
                ),
                (
                    lambda: _locked_switch_gate(function, sends, ctx),
                    "accepts the bet but pays the fixed prize only behind a bool switch a hidden role can flip",
                ),
                (
                    lambda: _straw_man(function, sends),
                    "pays the caller next to an external call on a settable state address (straw man)",
                ),
                (
                    # `selfdestruct(msg.sender)` is an exit too; the slot-0 quirk is send-kind agnostic.
                    lambda: _uninitialised_storage(function, all_sends),
                    "writes through an uninitialised storage pointer before paying the caller",
                ),
                (
                    lambda: _narrow_loop_counter(function, sends),
                    "loops on a narrow deduced counter against a wide bound before paying out",
                ),
            ]
            for check, reason in checks:
                node = check()
                if node is not None:
                    why = reason
                    break
        if node is None and contract_sends:
            node = _empty_string_call(function, ctx)
            if node is not None:
                why = "passes an empty string literal in a multi-argument external call (0.4 encoder skip)"
        if node is None:
            continue
        if function.name in seen:
            continue
        seen.add(function.name)
        findings.append(_emit("HONEYPOT_LEGACY", ctx, function, node, f"{function.name} {why}"))
    for site, node, why in _shadowed_role_hits(ctx):
        if site.name in seen:
            continue
        seen.add(site.name)
        findings.append(_emit("HONEYPOT_LEGACY", ctx, site, node, why))
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
