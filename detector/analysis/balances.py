"""Balance / supply / allowance binding and debit-credit-set classification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from slither.core.cfg.node import Node
from slither.core.declarations.function import Function
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable
from slither.slithir.variables.temporary import TemporaryVariable
from slither.slithir.operations import (
    Assignment,
    Binary,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    Return,
    SolidityCall,
    TypeConversion,
    Unary,
)
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables.constant import Constant
from slither.slithir.variables.reference import ReferenceVariable

from detector.analysis._ir import (
    SIG_ALLOWANCE,
    SIG_APPROVE,
    SIG_BALANCE_OF,
    SIG_TOTAL_SUPPLY,
    THIS,
    assert_never,
    callee_of,
    depends,
    fn_ir,
    index_chain,
    is_addr_to_uint_mapping,
    is_address_var,
    is_ctor,
    is_externally_callable,
    is_msg_sender,
    is_this_expr,
    is_uint_type,
    iter_internal_callees,
    root_state,
    solidity_sig,
    sorted_vars,
    unique_functions,
    values_feeding_condition,
    var_sort_key,
)

KeySource = Literal["from", "to", "msg.sender", "param", "state", "this", "other"]
WriteKind = Literal["debit", "credit", "set"]
ArithKind = Literal["add", "sub"]


@dataclass(frozen=True)
class Bindings:
    balance_vars: tuple[StateVariable, ...]
    supply_vars: tuple[StateVariable, ...]
    allowance_vars: tuple[StateVariable, ...]
    balance_of: Function | None
    total_supply: Function | None


@dataclass(frozen=True)
class BalanceWrite:
    node: Node
    function: Function
    var: StateVariable
    key: Variable | None
    key_source: KeySource
    kind: WriteKind
    value: Variable | None
    value_is_raw_amount: bool
    value_reads_same_key: bool


def _fn_by_sig(contract: Any, signature: str) -> list[Function]:
    found: list[Function] = []
    for fn in unique_functions(contract):
        if solidity_sig(fn) == signature and fn.is_implemented:
            found.append(fn)
    return found


def _state_vars_on_returns(fn: Function) -> list[StateVariable]:
    found: list[StateVariable] = []
    seen: set[int] = set()

    def add(var: StateVariable | None) -> None:
        if var is None or id(var) in seen:
            return
        seen.add(id(var))
        found.append(var)

    for rv in fn.return_values or []:
        add(root_state(rv, fn))
        if isinstance(rv, StateVariable):
            add(rv)
        for sv in sorted_vars(fn.state_variables_read):
            if depends(rv, sv, fn):
                add(sv)
    for node in fn.nodes:
        for ir in node.irs:
            if not isinstance(ir, Return):
                continue
            for val in ir.values:
                add(root_state(val, fn))
                if isinstance(val, StateVariable):
                    add(val)
                for sv in sorted_vars(fn.state_variables_read):
                    if depends(val, sv, fn):
                        add(sv)
    for _, callee in iter_internal_callees(fn):
        if callee.view or callee.pure:
            for sv in _state_vars_on_returns(callee):
                add(sv)
    return found


def _keyed_by_address_param(var: StateVariable, fn: Function) -> bool:
    if is_addr_to_uint_mapping(var):
        return True
    addr_params = [p for p in fn.parameters if is_address_var(p)]
    if not addr_params:
        return False
    for node in fn.nodes:
        for ir in node.irs:
            if not isinstance(ir, Index):
                continue
            if root_state(ir.lvalue, fn) is not var and root_state(ir.variable_left, fn) is not var:
                continue
            key = ir.variable_right
            if key in addr_params or any(depends(key, p, fn) for p in addr_params):
                return True
    return bool(is_addr_to_uint_mapping(var))


def _public_named_mapping(contract: Any, name: str) -> StateVariable | None:
    for var in sorted_vars(contract.state_variables):
        if var.name != name:
            continue
        if var.visibility != "public":
            continue
        if name == "balanceOf" and is_addr_to_uint_mapping(var):
            return var
        if name == "totalSupply" and is_uint_type(var.type):
            return var
        if name == "allowance":
            typ = var.type
            inner = getattr(typ, "type_to", None)
            if isinstance(typ, MappingType) and isinstance(inner, MappingType):
                return var
    return None


def _debit_credit_fallback(contract: Any) -> tuple[StateVariable, ...] | None:
    for fn in unique_functions(contract):
        if is_ctor(fn) or not is_externally_callable(fn):
            continue
        writes = balance_writes(fn, Bindings((), (), (), None, None), param_roles=None)
        # Without bindings we still classify mapping(address=>uint) writes via bind-less scan.
        _ = writes
    # Dedicated scan: one public function that subtracts at msg.sender key and adds at another.
    for fn in unique_functions(contract):
        if is_ctor(fn) or not is_externally_callable(fn):
            continue
        debit_vars: set[int] = set()
        credit_vars: set[int] = set()
        sender_debit = False
        other_credit = False
        chosen: StateVariable | None = None
        for node in fn.nodes:
            for ir in node.irs:
                var, key, kind, _value = _classify_mapping_write(node, fn, ir, None)
                if var is None or kind is None:
                    continue
                if not is_addr_to_uint_mapping(var):
                    continue
                chosen = var
                if kind == "debit":
                    debit_vars.add(id(var))
                    src = _key_source(key, fn, None)
                    if src == "msg.sender":
                        sender_debit = True
                elif kind == "credit":
                    credit_vars.add(id(var))
                    src = _key_source(key, fn, None)
                    if src != "msg.sender":
                        other_credit = True
                else:
                    assert_never(kind) if kind not in ("debit", "credit", "set") else None
        if chosen is not None and sender_debit and other_credit and id(chosen) in debit_vars and id(chosen) in credit_vars:
            return (chosen,)
    return None


def _paired_ledger_fallback(
    contract: Any,
) -> tuple[tuple[StateVariable, ...], tuple[StateVariable, ...]] | None:
    """Ledger invariant without an ERC-20 ABI: one function moves a `mapping(address=>uint)`
    slot and a plain `uint` state var in the same direction by the same amount
    (`m[k] -= x; supply -= x;`). The pair is (balances, supply); a lone mapping is never bound."""
    for fn in unique_functions(contract):
        if is_ctor(fn) or not is_externally_callable(fn):
            continue
        helper = fn_ir(fn)
        map_moves: list[tuple[StateVariable, WriteKind, Any]] = []
        scalar_moves: list[tuple[StateVariable, WriteKind, Any]] = []
        for node in fn.nodes:
            for ir in node.irs:
                var, _key, kind, value = _classify_mapping_write(node, fn, ir, None)
                if var is None or kind not in ("credit", "debit") or value is None or var.is_constant:
                    continue
                if is_addr_to_uint_mapping(var):
                    map_moves.append((var, kind, value))
                elif is_uint_type(var.type) and not isinstance(var.type, MappingType):
                    scalar_moves.append((var, kind, value))
        for m_var, m_kind, m_val in map_moves:
            for s_var, s_kind, s_val in scalar_moves:
                if m_kind != s_kind:
                    continue
                same = m_val is s_val or helper.unwrap(m_val) is helper.unwrap(s_val)
                if same or depends(s_val, m_val, fn) or depends(m_val, s_val, fn):
                    return (m_var,), (s_var,)
    return None


def _allowance_fallback(contract: Any) -> tuple[StateVariable, ...] | None:
    approves = _fn_by_sig(contract, SIG_APPROVE)
    for fn in approves:
        if not is_externally_callable(fn):
            continue
        for node in fn.nodes:
            for ir in node.irs:
                if not isinstance(ir, Assignment):
                    continue
                lval = ir.lvalue
                root = root_state(lval, fn)
                if root is None:
                    continue
                _origin, keys = index_chain(lval, fn)
                if len(keys) < 2:
                    helper = fn_ir(fn)
                    # two-level Index: m[msg.sender][param]
                    cur = lval
                    collected: list[Any] = []
                    while isinstance(cur, ReferenceVariable):
                        defn = helper.def_of(cur)
                        if isinstance(defn, Index):
                            collected.append(defn.variable_right)
                            cur = defn.variable_left
                            continue
                        break
                    keys = collected
                if len(keys) >= 2 and is_msg_sender(fn_ir(fn).unwrap(keys[-1]) if False else keys[-1]):
                    pass
                if keys and (is_msg_sender(keys[-1]) or is_msg_sender(fn_ir(fn).unwrap(keys[-1]))):
                    return (root,)
                if keys and is_msg_sender(fn_ir(fn).unwrap(keys[-1])):
                    return (root,)
    # Prefer outer key msg.sender: keys are collected inner-first in index_chain.
    for fn in approves:
        for node in fn.nodes:
            for ir in node.irs:
                if not isinstance(ir, (Assignment, Binary)):
                    continue
                lval = ir.lvalue if isinstance(ir, (Assignment, Binary)) else None
                if lval is None:
                    continue
                root, keys = index_chain(lval, fn)
                helper = fn_ir(fn)
                unwrapped = [helper.unwrap(k) for k in keys]
                if root is not None and any(is_msg_sender(k) for k in unwrapped):
                    return (root,)
    return None


def bind(contract: Any) -> Bindings:
    balance_of: Function | None = None
    balance_vars: list[StateVariable] = []
    for fn in _fn_by_sig(contract, SIG_BALANCE_OF):
        deps = [sv for sv in _state_vars_on_returns(fn) if _keyed_by_address_param(sv, fn)]
        if deps:
            balance_of = fn
            for sv in deps:
                if sv not in balance_vars:
                    balance_vars.append(sv)
            break
    if not balance_vars:
        named = _public_named_mapping(contract, "balanceOf")
        if named is not None:
            balance_vars.append(named)
            getters = _fn_by_sig(contract, SIG_BALANCE_OF)
            balance_of = getters[0] if getters else None
    if not balance_vars:
        fallback = _debit_credit_fallback(contract)
        if fallback:
            balance_vars.extend(fallback)

    total_supply: Function | None = None
    supply_vars: list[StateVariable] = []
    for fn in _fn_by_sig(contract, SIG_TOTAL_SUPPLY):
        deps = []
        for sv in _state_vars_on_returns(fn):
            if is_uint_type(sv.type) or sv.is_constant:
                deps.append(sv)
        if deps:
            total_supply = fn
            for sv in deps:
                if sv not in supply_vars:
                    supply_vars.append(sv)
            break
    if not supply_vars:
        named = _public_named_mapping(contract, "totalSupply")
        if named is not None:
            supply_vars.append(named)
            getters = _fn_by_sig(contract, SIG_TOTAL_SUPPLY)
            total_supply = getters[0] if getters else None
    if not balance_vars and not supply_vars:
        paired = _paired_ledger_fallback(contract)
        if paired is not None:
            balance_vars.extend(paired[0])
            supply_vars.extend(paired[1])

    allowance_vars: list[StateVariable] = []
    for fn in _fn_by_sig(contract, SIG_ALLOWANCE):
        deps = _state_vars_on_returns(fn)
        if deps:
            for sv in deps:
                if sv not in allowance_vars:
                    allowance_vars.append(sv)
            break
    if not allowance_vars:
        named = _public_named_mapping(contract, "allowance")
        if named is not None:
            allowance_vars.append(named)
    if not allowance_vars:
        fallback = _allowance_fallback(contract)
        if fallback:
            allowance_vars.extend(fallback)

    return Bindings(
        balance_vars=tuple(balance_vars),
        supply_vars=tuple(supply_vars),
        allowance_vars=tuple(allowance_vars),
        balance_of=balance_of,
        total_supply=total_supply,
    )


def arith_kind(call: InternalCall | LibraryCall) -> ArithKind | None:
    callee = callee_of(call)
    if callee is None:
        return None
    if callee.state_variables_written:
        return None
    params = list(callee.parameters or [])
    if len(params) != 2:
        return None
    helper = fn_ir(callee)
    returned: list[Any] = []
    for rv in callee.return_values or []:
        returned.append(rv)
    for node in callee.nodes:
        for ir in node.irs:
            if isinstance(ir, Return):
                returned.extend(ir.values)

    def as_binary(val: Any) -> Binary | None:
        cur = val
        for _ in range(8):
            ir = helper.def_of(cur)
            if isinstance(ir, Binary) and ir.type in (BinaryType.ADDITION, BinaryType.SUBTRACTION):
                return ir
            if isinstance(ir, Assignment):
                cur = ir.rvalue
                continue
            break
        return None

    for val in returned:
        binary = as_binary(val)
        if binary is None:
            continue
        left = helper.unwrap(binary.variable_left)
        right = helper.unwrap(binary.variable_right)
        if {id(left), id(right)} != {id(params[0]), id(params[1])} and {left, right} != set(params):
            # Allow the operands to be the two parameters even if identity differs via unwrap.
            ends = {id(helper.unwrap(params[0])), id(helper.unwrap(params[1]))}
            if {id(left), id(right)} != ends and not (
                (left in params or helper.unwrap(left) in params)
                and (right in params or helper.unwrap(right) in params)
            ):
                continue
        if binary.type == BinaryType.ADDITION:
            return "add"
        if binary.type == BinaryType.SUBTRACTION:
            return "sub"
        assert_never(binary.type)
    return None


def _same_mapping_key(ref: Any, var: StateVariable, key: Any, function: Function) -> bool:
    root, keys = index_chain(ref, function)
    if root is not var:
        return False
    if not keys:
        return True
    helper = fn_ir(function)
    return helper.unwrap(keys[0]) is helper.unwrap(key) or keys[0] is key


def _classify_mapping_write(
    node: Node,
    function: Function,
    ir: Any,
    bound: tuple[StateVariable, ...] | None,
) -> tuple[StateVariable | None, Any, WriteKind | None, Any]:
    lval = getattr(ir, "lvalue", None)
    if lval is None:
        return None, None, None, None
    var = root_state(lval, function)
    if var is None:
        return None, None, None, None
    if bound is not None and var not in bound:
        return None, None, None, None
    _root, keys = index_chain(lval, function)
    key = keys[0] if keys else None
    helper = fn_ir(function)
    kind: WriteKind | None = None
    value: Any = None
    if isinstance(ir, Binary) and ir.type in (BinaryType.ADDITION, BinaryType.SUBTRACTION):
        left = ir.variable_left
        right = ir.variable_right
        if _same_mapping_key(left, var, key, function) or left is lval:
            kind = "credit" if ir.type == BinaryType.ADDITION else "debit"
            value = right
        else:
            kind = "set"
            value = ir.lvalue
    elif isinstance(ir, Assignment):
        rval = ir.rvalue
        call = helper.def_of(rval) if not isinstance(rval, (InternalCall, LibraryCall)) else rval
        if isinstance(rval, (InternalCall, LibraryCall)):
            call = rval
        ak = arith_kind(call) if isinstance(call, (InternalCall, LibraryCall)) else None
        if ak is not None and isinstance(call, (InternalCall, LibraryCall)):
            args = list(call.arguments or [])
            if len(args) >= 2 and _same_mapping_key(args[0], var, key, function):
                kind = "credit" if ak == "add" else "debit"
                value = args[1]
            elif ak == "add":
                kind = "credit"
                value = args[1] if len(args) > 1 else rval
            elif ak == "sub":
                kind = "debit"
                value = args[1] if len(args) > 1 else rval
            else:
                assert_never(ak)
        else:
            bin_ir = helper.def_of(rval)
            if isinstance(bin_ir, Binary) and bin_ir.type in (BinaryType.ADDITION, BinaryType.SUBTRACTION):
                if _same_mapping_key(bin_ir.variable_left, var, key, function):
                    kind = "credit" if bin_ir.type == BinaryType.ADDITION else "debit"
                    value = bin_ir.variable_right
                else:
                    kind = "set"
                    value = rval
            else:
                kind = "set"
                value = rval
    else:
        return None, None, None, None
    return var, key, kind, value


def _key_source(key: Any, function: Function, param_roles: dict[Variable, str] | None) -> KeySource:
    if key is None:
        return "other"
    helper = fn_ir(function)
    cur = helper.unwrap(key)
    if is_msg_sender(cur) or is_msg_sender(key):
        return "msg.sender"
    if is_this_expr(cur, function) or cur is THIS or is_this_expr(key, function):
        return "this"
    if isinstance(cur, StateVariable) or isinstance(key, StateVariable):
        return "state"
    role = None
    if param_roles:
        role = param_roles.get(cur) or param_roles.get(key)
        if role is None:
            ordered = sorted(
                param_roles.items(),
                key=lambda item: (*var_sort_key(item[0]), item[1]),
            )
            exact = [tagged for param, tagged in ordered if param is cur or param is key]
            if exact:
                role = exact[0]
            else:
                deps = [
                    tagged
                    for param, tagged in ordered
                    if depends(cur, param, function)
                ]
                if deps:
                    role = deps[0]
    if role in ("from", "to"):
        return role  # type: ignore[return-value]
    if role == "amount":
        return "param"
    if cur in function.parameters or key in function.parameters:
        return "param"
    if isinstance(cur, Variable) and cur in function.parameters:
        return "param"
    return "other"


def _is_raw_amount(value: Any, function: Function, param_roles: dict[Variable, str] | None) -> bool:
    if value is None or not param_roles:
        return False
    amounts = [param for param, role in param_roles.items() if role == "amount"]
    if not amounts:
        return False
    helper = fn_ir(function)
    cur: Any = value
    seen: set[int] = set()
    for _ in range(12):
        if cur is None or id(cur) in seen:
            return False
        seen.add(id(cur))
        if cur in amounts:
            return True
        ir = helper.def_of(cur)
        if isinstance(ir, (Binary, Unary)):
            return False
        if isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
            return False
        if isinstance(ir, TypeConversion):
            cur = ir.variable
            continue
        if isinstance(ir, Assignment):
            cur = ir.rvalue
            continue
        break
    unwrapped = helper.unwrap(value)
    return unwrapped in amounts or value in amounts


def _value_reads_same_key(
    value: Any,
    var: StateVariable,
    key: Any,
    function: Function,
    bindings: Bindings,
) -> bool:
    if value is None:
        return False
    bound = bindings.balance_vars or (var,)
    helper = fn_ir(function)
    cur = value
    ir = helper.def_of(cur)
    candidates = [cur]
    if isinstance(ir, Binary):
        candidates.extend([ir.variable_left, ir.variable_right])
    if isinstance(ir, (InternalCall, LibraryCall)):
        candidates.extend(ir.arguments or [])
    for cand in candidates:
        root, keys = index_chain(cand, function)
        if root is None:
            root = root_state(cand, function)
        if root in bound and root is var:
            if key is None or not keys:
                return True
            if helper.unwrap(keys[0]) is helper.unwrap(key) or keys[0] is key:
                return True
        if depends(cand, var, function) and _same_mapping_key(cand, var, key, function):
            return True
    return False


def balance_writes(
    function: Function,
    bindings: Bindings,
    param_roles: dict[Variable, str] | None = None,
) -> list[BalanceWrite]:
    bound = bindings.balance_vars
    # When bind is empty (fallback scan), classify any address→uint mapping write.
    out: list[BalanceWrite] = []
    seen: set[tuple[int, int]] = set()
    for node in function.nodes:
        for ir in node.irs:
            var, key, kind, value = _classify_mapping_write(
                node, function, ir, bound if bound else None
            )
            if var is None or kind is None:
                continue
            if bound and var not in bound:
                continue
            if not bound and not is_addr_to_uint_mapping(var):
                continue
            # Pair identity, not XOR: id(a) ^ id(b) collides when pointers are
            # close (typical pymalloc) and drops writes across processes.
            pair = (id(node), id(ir))
            if pair in seen:
                continue
            seen.add(pair)
            src = _key_source(key, function, param_roles)
            if src not in ("from", "to", "msg.sender", "param", "state", "this", "other"):
                assert_never(src)
            if kind not in ("debit", "credit", "set"):
                assert_never(kind)
            out.append(
                BalanceWrite(
                    node=node,
                    function=function,
                    var=var,
                    key=key if isinstance(key, Variable) or key is None else key,
                    key_source=src,
                    kind=kind,
                    value=value if isinstance(value, Variable) or value is None else value,
                    value_is_raw_amount=_is_raw_amount(value, function, param_roles),
                    value_reads_same_key=_value_reads_same_key(value, var, key, function, bindings),
                )
            )
    return out


def condition_roots(node: Node) -> list[Any]:
    """Resolve condition operands to same-function roots (state / const / call / param)."""
    function = node.function
    helper = fn_ir(function)
    params = set(function.parameters or [])
    out: list[Any] = []
    seen_out: set[int] = set()

    def add(item: Any) -> None:
        if item is None or id(item) in seen_out:
            return
        seen_out.add(id(item))
        out.append(item)

    def walk(var: Any, depth: int, seen: set[int]) -> None:
        if var is None or depth <= 0 or id(var) in seen:
            return
        seen = seen | {id(var)}
        if isinstance(var, (StateVariable, Constant)) or var in params:
            add(var)
            return
        if not isinstance(var, (LocalVariable, TemporaryVariable)):
            add(var)
            return
        ir = helper.def_of(var)
        if ir is None:
            add(var)
            return
        if isinstance(ir, Assignment):
            walk(ir.rvalue, depth - 1, seen)
            return
        if isinstance(ir, Binary):
            walk(ir.variable_left, depth - 1, seen)
            walk(ir.variable_right, depth - 1, seen)
            return
        if isinstance(ir, TypeConversion):
            walk(ir.variable, depth - 1, seen)
            return
        if isinstance(ir, Unary):
            walk(ir.rvalue, depth - 1, seen)
            return
        if isinstance(ir, (InternalCall, LibraryCall)):
            add(ir)
            return
        add(var)

    for val in values_feeding_condition(node):
        walk(val, 12, set())
    return out


def is_constant_bound(condition_node: Node, ctx: Any) -> bool:
    bindings: Bindings = ctx.bindings
    pw = set(ctx.privileged_writable.keys())
    supply = set(bindings.supply_vars)
    allowed_pw = supply
    involved_state: list[StateVariable] = []
    for var in values_feeding_condition(condition_node):
        root = root_state(var, condition_node.function)
        if isinstance(root, StateVariable):
            involved_state.append(root)
        if isinstance(var, StateVariable):
            involved_state.append(var)
    for sv in condition_node.state_variables_read:
        involved_state.append(sv)
    helper = fn_ir(condition_node.function)
    for ir in condition_node.irs:
        if isinstance(ir, (InternalCall, LibraryCall)):
            callee = callee_of(ir)
            if callee is not None and bindings.total_supply is not None:
                if callee is bindings.total_supply or solidity_sig(callee) == SIG_TOTAL_SUPPLY:
                    continue
            if callee is not None:
                for sv in callee.state_variables_read:
                    involved_state.append(sv)
        if isinstance(ir, SolidityCall):
            continue
        _ = helper
    roots = condition_roots(condition_node)
    for root in roots:
        if isinstance(root, StateVariable):
            involved_state.append(root)
        if isinstance(root, (InternalCall, LibraryCall)):
            callee = callee_of(root)
            if callee is not None:
                for sv in callee.state_variables_read:
                    involved_state.append(sv)
    for sv in involved_state:
        if sv in pw and sv not in allowed_pw:
            return False
        if sv in pw and sv not in supply:
            return False
    # Must involve a literal / constant / immutable / supply — not only params.
    has_bound = False
    for sv in involved_state:
        if sv.is_constant or sv.is_immutable or sv in supply:
            has_bound = True
    for ir in condition_node.irs:
        if isinstance(ir, Binary):
            for side in (ir.variable_left, ir.variable_right):
                if isinstance(side, Constant):
                    has_bound = True
        if isinstance(ir, (InternalCall, LibraryCall)):
            callee = callee_of(ir)
            if callee is not None and (
                (bindings.total_supply is not None and callee is bindings.total_supply)
                or solidity_sig(callee) == SIG_TOTAL_SUPPLY
            ):
                has_bound = True
    for root in roots:
        if isinstance(root, Constant):
            has_bound = True
        if isinstance(root, StateVariable) and (root.is_constant or root.is_immutable or root in supply):
            has_bound = True
        if isinstance(root, (InternalCall, LibraryCall)):
            callee = callee_of(root)
            if callee is not None and (
                (bindings.total_supply is not None and callee is bindings.total_supply)
                or solidity_sig(callee) == SIG_TOTAL_SUPPLY
            ):
                has_bound = True
    return has_bound
