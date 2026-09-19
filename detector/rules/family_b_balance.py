"""Family B: privileged mint/burn/set, hidden mint on transfer, lying views."""

from __future__ import annotations

from detector.analysis import balances, privilege, roles
from detector.analysis._ir import (
    MSG_SENDER,
    TX_ORIGIN,
    branch_reverts_before_write,
    depends,
    false_son,
    fn_ir,
    is_ctor,
    is_if_node,
    is_modifier,
    is_msg_sender,
    is_require_assert_node,
    is_tx_origin,
    iter_internal_callees,
    root_state,
    true_son,
    values_feeding_condition,
)
from detector.analysis.balances import arith_kind, balance_writes
from detector.analysis.context import ContractContext
from detector.analysis.transfer_path import _path_meta
from detector.model import Finding
from detector.rules.base import (
    contract_name,
    function_name,
    make_finding,
    node_lines,
    shape_discriminators,
)
from slither.slithir.operations import Assignment, Binary, InternalCall, LibraryCall, Return
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables.constant import Constant

_MINT_KEYS = frozenset({"param", "state", "this", "msg.sender"})


def _cname(ctx: ContractContext) -> str:
    return contract_name(ctx.contract)


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


def _privileged_mode_functions(ctx: ContractContext) -> list:
    seen: set[int] = set()
    out = []
    for pw in ctx.privileged_writes:
        if pw.mode != "function":
            continue
        fn = pw.function
        if is_ctor(fn) or is_modifier(fn):
            continue
        if fn in ctx.transfer_path:
            continue
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        out.append(fn)
    return out


def _const_zero(var, function) -> bool:
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
        return _const_zero(getattr(ir, "variable", None), function)
    return False


def _remap_key_source(write, caller, ir) -> str:
    key = write.key
    if key is None:
        return write.key_source
    args = list(ir.arguments or [])
    params = list(write.function.parameters or [])
    helper = fn_ir(caller)
    for idx, param in enumerate(params):
        if param is not key and helper.unwrap(key) is not param:
            continue
        if idx >= len(args):
            break
        arg = args[idx]
        if is_msg_sender(arg) or is_msg_sender(helper.unwrap(arg)):
            return "msg.sender"
    return write.key_source


def _clone_write(write, *, function, key_source):
    return type(write)(
        node=write.node,
        function=function,
        var=write.var,
        key=write.key,
        key_source=key_source,
        kind=write.kind,
        value=write.value,
        value_is_raw_amount=write.value_is_raw_amount,
        value_reads_same_key=write.value_reads_same_key,
    )


def _callee_writes(fn, ctx: ContractContext) -> list:
    """balance_writes on fn plus callees, remapping msg.sender keys from call args.

    Gap: balances.balance_writes does not walk callees; USDC mint/burn write
    through helpers. Remap here instead of patching analysis.
    """
    out = list(balance_writes(fn, ctx.bindings))
    for ir, callee in iter_internal_callees(fn):
        for write in balance_writes(callee, ctx.bindings):
            source = _remap_key_source(write, fn, ir)
            out.append(_clone_write(write, function=fn, key_source=source))
    return out


def _supply_changes(function, supply_vars) -> set[str]:
    found: set[str] = set()
    ids = {id(v) for v in supply_vars}
    if not ids:
        return found
    helper = fn_ir(function)
    for node in function.nodes:
        for ir in node.irs:
            lval = getattr(ir, "lvalue", None)
            if lval is None:
                continue
            root = lval if id(lval) in ids else root_state(lval, function)
            if root is None or id(root) not in ids:
                continue
            if isinstance(ir, Binary):
                if ir.type == BinaryType.ADDITION:
                    found.add("inc")
                elif ir.type == BinaryType.SUBTRACTION:
                    found.add("dec")
                continue
            if not isinstance(ir, Assignment):
                continue
            call = ir.rvalue if isinstance(ir.rvalue, (InternalCall, LibraryCall)) else helper.def_of(ir.rvalue)
            ak = arith_kind(call) if isinstance(call, (InternalCall, LibraryCall)) else None
            if ak == "add":
                found.add("inc")
            elif ak == "sub":
                found.add("dec")
            else:
                bin_ir = helper.def_of(ir.rvalue)
                if isinstance(bin_ir, Binary) and bin_ir.type == BinaryType.ADDITION:
                    found.add("inc")
                elif isinstance(bin_ir, Binary) and bin_ir.type == BinaryType.SUBTRACTION:
                    found.add("dec")
    return found


def _local_ends(function) -> list:
    out = []
    for node in function.nodes:
        if is_require_assert_node(node):
            out.append(node)
        elif is_if_node(node) and (
            branch_reverts_before_write(true_son(node))
            or branch_reverts_before_write(false_son(node))
        ):
            out.append(node)
    return out


def _reads_supply(node, ctx: ContractContext) -> bool:
    supply = set(ctx.bindings.supply_vars)
    if any(sv in supply for sv in node.state_variables_read):
        return True
    total = ctx.bindings.total_supply
    if total is None:
        return False
    for ir in node.irs:
        if isinstance(ir, (InternalCall, LibraryCall)) and ir.function is total:
            return True
    return False


def _constant_cap(fn, ctx: ContractContext) -> bool:
    for site in _closure(fn):
        for node in _local_ends(site):
            if _reads_supply(node, ctx) and balances.is_constant_bound(node, ctx):
                return True
    return False


def _role_separated_cap(fn, ctx: ContractContext) -> bool:
    minter_auth = {id(atom.auth_var) for atom in privilege.auth_atoms(fn)}
    skip = {id(v) for v in ctx.bindings.balance_vars} | {id(v) for v in ctx.bindings.supply_vars}
    for site in _closure(fn):
        for node in _local_ends(site):
            for sv in node.state_variables_read:
                if sv not in ctx.privileged_writable:
                    continue
                if id(sv) in skip:
                    continue
                writer_auth: set[int] = set()
                for pw in ctx.privileged_writable[sv]:
                    writer_auth.update(id(v) for v in pw.auth_vars)
                if writer_auth and writer_auth.isdisjoint(minter_auth):
                    return True
    return False


def _mint_discs(ctx: ContractContext, fn) -> tuple[str, ...]:
    extra: list[str] = []
    if _constant_cap(fn, ctx):
        extra.append("constant_cap")
    if _role_separated_cap(fn, ctx):
        extra.append("role_separated_cap")
    discs = tuple(extra) + shape_discriminators(ctx, fn)
    if roles.issuer_token(ctx) and "issuer_token" not in discs:
        discs = discs + ("issuer_token",)
    return discs


def _other_bound_balance_at_key(write, ctx: ContractContext) -> bool:
    if write.value is None:
        return False
    bound = [v for v in ctx.bindings.balance_vars if v is not write.var]
    if not bound:
        return False
    fn = write.function
    for other in bound:
        if depends(write.value, other, fn) or root_state(write.value, fn) is other:
            return True
    return False


def _selector_map_written(fn, ctx: ContractContext) -> bool:
    view = ctx.bindings.balance_of
    if view is None:
        return False
    selectors = []
    for node in view.nodes:
        if not is_if_node(node):
            continue
        for sv in node.state_variables_read:
            if sv not in ctx.bindings.balance_vars:
                selectors.append(sv)
    if not selectors:
        return False
    for node in fn.nodes:
        written = set(node.state_variables_written)
        if any(sel in written for sel in selectors):
            return True
    return False


def _representation_switch(ctx: ContractContext, fn, write) -> bool:
    if _other_bound_balance_at_key(write, ctx):
        return True
    if write.kind == "set" and _const_zero(write.value, write.function):
        if _selector_map_written(fn, ctx):
            return True
    return False


def _fn_discs(ctx: ContractContext, fn, extra: tuple[str, ...] = ()) -> tuple[str, ...]:
    discs = extra + shape_discriminators(ctx, fn)
    if roles.issuer_token(ctx) and "issuer_token" not in discs:
        discs = discs + ("issuer_token",)
    return discs


def BAL_PRIV_MINT(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    for fn in _privileged_mode_functions(ctx):
        writes = _callee_writes(fn, ctx)
        mint_writes = [
            w
            for w in writes
            if w.var in ctx.bindings.balance_vars
            and w.key_source in _MINT_KEYS
            and (w.kind == "credit" or (w.kind == "set" and w.value_reads_same_key))
        ]
        supply_inc = any("inc" in _supply_changes(site, ctx.bindings.supply_vars) for site in _closure(fn))
        if not mint_writes and not supply_inc:
            continue
        node = mint_writes[0].node if mint_writes else fn.entry_point
        out.append(
            make_finding(
                "BAL_PRIV_MINT",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(node) if node is not None else (),
                reasoning=f"{function_name(fn)} increases bound balance or supply",
                discriminators=_mint_discs(ctx, fn),
            )
        )
    return out


def BAL_PRIV_BURN_OTHER(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    for fn in _privileged_mode_functions(ctx):
        hits = []
        for write in _callee_writes(fn, ctx):
            if write.var not in ctx.bindings.balance_vars:
                continue
            if write.key_source == "msg.sender":
                continue
            is_zero_set = write.kind == "set" and _const_zero(write.value, write.function)
            if write.kind != "debit" and not is_zero_set:
                continue
            hits.append(write)
        if not hits:
            continue
        extra: tuple[str, ...] = ()
        if any(_representation_switch(ctx, fn, w) for w in hits):
            extra = ("representation_switch",)
        out.append(
            make_finding(
                "BAL_PRIV_BURN_OTHER",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(hits[0].node),
                reasoning=f"{function_name(fn)} debits bound balance at a non-sender key",
                discriminators=_fn_discs(ctx, fn, extra),
            )
        )
    return out


def BAL_DIRECT_SET(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    for fn in _privileged_mode_functions(ctx):
        hits = [
            w
            for w in balance_writes(fn, ctx.bindings)
            if w.var in ctx.bindings.balance_vars
            and w.kind == "set"
            and not w.value_reads_same_key
            and w.key_source in ("param", "state")
            and not _const_zero(w.value, fn)
        ]
        if not hits:
            continue
        extra: tuple[str, ...] = ()
        if any(_representation_switch(ctx, fn, w) for w in hits):
            extra = ("representation_switch",)
        out.append(
            make_finding(
                "BAL_DIRECT_SET",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(hits[0].node),
                reasoning=f"{function_name(fn)} assigns bound balance without reading the same key",
                discriminators=_fn_discs(ctx, fn, extra),
            )
        )
    return out


def BAL_TRANSFER_HIDDEN_MINT(ctx: ContractContext) -> list[Finding]:
    meta = _path_meta(ctx)
    credits = []
    for fn in ctx.transfer_path:
        if is_ctor(fn) or is_modifier(fn):
            continue
        roles_map = meta.roles.get(id(fn), {})
        for write in balance_writes(fn, ctx.bindings, param_roles=roles_map or None):
            if write.kind == "credit":
                credits.append((fn, write))
    if len(credits) < 2:
        return []
    other_raw = [item for item in credits if item[1].key_source != "to" and item[1].value_is_raw_amount]
    to_raw = [item for item in credits if item[1].key_source == "to" and item[1].value_is_raw_amount]
    other_raw_any = any(item[1].value_is_raw_amount and item[1].key_source != "to" for item in credits)
    if not other_raw and not (to_raw and other_raw_any):
        return []
    fn, write = (other_raw or to_raw or credits)[0]
    return [
        make_finding(
            "BAL_TRANSFER_HIDDEN_MINT",
            contract=_cname(ctx),
            function=function_name(fn),
            lines=node_lines(write.node),
            reasoning=(
                f"{function_name(fn)} credits raw amount to a key other than to, or double-credits"
            ),
        )
    ]


def _caller_tainted(fn) -> bool:
    for rv in fn.return_values or []:
        if depends(rv, MSG_SENDER, fn) or depends(rv, TX_ORIGIN, fn):
            return True
        if is_msg_sender(rv) or is_tx_origin(rv):
            return True
    for node in fn.nodes:
        if is_if_node(node):
            for val in values_feeding_condition(node):
                if is_msg_sender(val) or is_tx_origin(val):
                    return True
                if depends(val, MSG_SENDER, fn) or depends(val, TX_ORIGIN, fn):
                    return True
        for ir in node.irs:
            if not isinstance(ir, Return):
                continue
            for val in ir.values:
                if is_msg_sender(val) or is_tx_origin(val):
                    return True
                if depends(val, MSG_SENDER, fn) or depends(val, TX_ORIGIN, fn):
                    return True
    return False


def VIEW_CALLER_DEPENDENT(ctx: ContractContext) -> list[Finding]:
    out: list[Finding] = []
    for fn in (ctx.bindings.balance_of, ctx.bindings.total_supply):
        if fn is None:
            continue
        if not _caller_tainted(fn):
            continue
        node = fn.entry_point
        for cand in fn.nodes:
            if is_if_node(cand):
                node = cand
                break
        out.append(
            make_finding(
                "VIEW_CALLER_DEPENDENT",
                contract=_cname(ctx),
                function=function_name(fn),
                lines=node_lines(node) if node is not None else (),
                reasoning=f"{function_name(fn)} return or branch depends on msg.sender or tx.origin",
            )
        )
    return out


RULES = [
    BAL_PRIV_MINT,
    BAL_PRIV_BURN_OTHER,
    BAL_DIRECT_SET,
    BAL_TRANSFER_HIDDEN_MINT,
    VIEW_CALLER_DEPENDENT,
]
