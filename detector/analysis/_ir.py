"""Shared Slither IR helpers for the name-agnostic analysis layer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Iterator

from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.core.cfg.node import Node, NodeType
from slither.core.declarations.function import Function
from slither.core.declarations.modifier import Modifier
from slither.core.declarations.solidity_variables import (
    SolidityCustomRevert,
    SolidityFunction,
    SolidityVariable,
    SolidityVariableComposed,
)
from slither.core.solidity_types.array_type import ArrayType
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable
from slither.slithir.operations import (
    Assignment,
    Binary,
    Condition,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Member,
    OperationWithLValue,
    Return,
    SolidityCall,
    TypeConversion,
    Unary,
)
from slither.slithir.operations.binary import BinaryType
from slither.slithir.operations.unary import UnaryType
from slither.slithir.variables.constant import Constant
from slither.slithir.variables.reference import ReferenceVariable

MSG_SENDER = SolidityVariableComposed("msg.sender")
TX_ORIGIN = SolidityVariableComposed("tx.origin")
MSG_VALUE = SolidityVariableComposed("msg.value")
BLOCK_TIMESTAMP = SolidityVariableComposed("block.timestamp")
BLOCK_NUMBER = SolidityVariableComposed("block.number")
THIS = SolidityVariable("this")

SIG_TRANSFER = "transfer(address,uint256)"
SIG_TRANSFER_FROM = "transferFrom(address,address,uint256)"
SIG_APPROVE = "approve(address,uint256)"
SIG_BALANCE_OF = "balanceOf(address)"
SIG_TOTAL_SUPPLY = "totalSupply()"
SIG_ALLOWANCE = "allowance(address,address)"

REQUIRE_ASSERT_NAMES = frozenset(
    {
        "require(bool)",
        "require(bool,string)",
        "require(bool,error)",
        "assert(bool)",
    }
)
REVERT_NAMES = frozenset({"revert()", "revert(string)"})
SELFDESTRUCT_NAMES = frozenset({"selfdestruct(address)", "suicide(address)"})
BALANCE_CALL_NAMES = frozenset({"balance(address)", "this.balance()"})

# Strong per-contract caches. Keys are live Slither objects held by the
# compilation (and by ContractContext); never WeakKey / bare id() globals.
CACHE_FNIR = "_t404_fnir"
CACHE_AUTH = "_t404_auth_atoms"
CACHE_BRANCH = "_t404_branch_atoms"
CACHE_PRIV = "_t404_priv_writes"


def assert_never(value: object) -> None:
    raise AssertionError(f"unhandled variant: {value!r}")


def source_file(obj: Any) -> Path | None:
    mapping = getattr(obj, "source_mapping", None)
    if mapping is None:
        return None
    filename = getattr(mapping, "filename", None)
    absolute = getattr(filename, "absolute", None) if filename is not None else None
    if not absolute:
        return None
    return Path(absolute).resolve()


def is_under_root(obj: Any, input_root: Path) -> bool:
    path = source_file(obj)
    if path is None:
        return False
    root = Path(input_root).resolve()
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def source_sort_key(obj: Any) -> tuple[str, int]:
    mapping = getattr(obj, "source_mapping", None)
    if mapping is None:
        return ("", 0)
    filename = getattr(mapping, "filename", None)
    absolute = getattr(filename, "absolute", None) or ""
    start = getattr(mapping, "start", 0) or 0
    return (absolute, start)


def var_sort_key(var: Any) -> tuple[str, str, int]:
    path, start = source_sort_key(var)
    return (getattr(var, "name", None) or "", path, start)


def node_sort_key(node: Node) -> tuple[str, int, int]:
    path, start = source_sort_key(node)
    return (path, start, getattr(node, "node_id", 0) or 0)


def function_sort_key(fn: Function) -> tuple[str, str, int]:
    path, start = source_sort_key(fn)
    return (solidity_sig(fn) if isinstance(fn, Function) else "", path, start)


def sorted_vars(vars_: Iterable[Any]) -> list[Any]:
    return sorted(vars_, key=var_sort_key)


def sorted_nodes(nodes: Iterable[Node]) -> list[Node]:
    return sorted(nodes, key=node_sort_key)


def contract_cache(contract: Any, attr: str) -> dict:
    cache = getattr(contract, attr, None)
    if cache is None:
        cache = {}
        try:
            setattr(contract, attr, cache)
        except Exception:
            return {}
    return cache


def pin_contract_caches(contract: Any) -> None:
    for attr in (CACHE_FNIR, CACHE_AUTH, CACHE_BRANCH):
        contract_cache(contract, attr)


def unique_functions(contract: Any) -> list[Function]:
    seen: set[int] = set()
    out: list[Function] = []
    declared = list(getattr(contract, "functions_and_modifiers_declared", []) or [])
    inherited = list(getattr(contract, "functions", []) or [])
    for fn in declared + inherited:
        key = id(fn)
        if key in seen:
            continue
        seen.add(key)
        out.append(fn)
    out.sort(key=function_sort_key)
    return out


def is_ctor(fn: Function) -> bool:
    return bool(fn.is_constructor or fn.is_constructor_variables)


def is_modifier(fn: Function) -> bool:
    return isinstance(fn, Modifier)


def is_externally_callable(fn: Function) -> bool:
    return fn.visibility in ("public", "external")


def solidity_sig(fn: Function) -> str:
    return fn.solidity_signature or fn.full_name


def elem_name(typ: Any) -> str | None:
    if isinstance(typ, ElementaryType):
        return typ.name
    return None


def is_address_type(typ: Any) -> bool:
    name = elem_name(typ)
    if name == "address":
        return True
    # Contract types are ABI addresses; used when converting `this` / token dest.
    inner = getattr(typ, "type", None)
    return inner is not None and inner.__class__.__name__ == "Contract"


def is_bool_type(typ: Any) -> bool:
    return elem_name(typ) == "bool"


def is_uint_type(typ: Any) -> bool:
    name = elem_name(typ)
    return bool(name) and name.startswith("uint")


def is_numeric_type(typ: Any) -> bool:
    name = elem_name(typ)
    return bool(name) and (name.startswith("uint") or name.startswith("int"))


def is_address_var(var: Any) -> bool:
    return is_address_type(getattr(var, "type", None))


def mapping_leaf_type(typ: Any) -> Any:
    cur = typ
    while isinstance(cur, MappingType):
        cur = cur.type_to
    while isinstance(cur, ArrayType):
        cur = cur.type
    return cur


def is_addr_to_uint_mapping(var: StateVariable) -> bool:
    typ = var.type
    if not isinstance(typ, MappingType):
        return False
    if not is_address_type(typ.type_from):
        return False
    return is_uint_type(typ.type_to)


def is_addr_bool_mapping(var: StateVariable) -> bool:
    typ = var.type
    if not isinstance(typ, MappingType):
        return False
    return is_address_type(typ.type_from) and is_bool_type(typ.type_to)


def is_msg_sender(var: Any) -> bool:
    return isinstance(var, SolidityVariableComposed) and var.name == "msg.sender"


def is_tx_origin(var: Any) -> bool:
    return isinstance(var, SolidityVariableComposed) and var.name == "tx.origin"


def is_msg_value(var: Any) -> bool:
    return isinstance(var, SolidityVariableComposed) and var.name == "msg.value"


def is_this(var: Any) -> bool:
    return isinstance(var, SolidityVariable) and not isinstance(var, SolidityVariableComposed) and var.name == "this"


def is_time_var(var: Any) -> bool:
    return isinstance(var, SolidityVariableComposed) and var.name in (
        "block.timestamp",
        "block.number",
        "now",
    )


def constant_bool(var: Any) -> bool | None:
    if isinstance(var, Constant) and isinstance(var.value, bool):
        return var.value
    return None


def solidity_call_name(ir: SolidityCall) -> str:
    fn = ir.function
    return getattr(fn, "name", "") or ""


def is_require_assert_node(node: Node) -> bool:
    if node.contains_require_or_assert():
        return True
    for ir in node.irs:
        if isinstance(ir, SolidityCall) and solidity_call_name(ir) in REQUIRE_ASSERT_NAMES:
            return True
    return False


def require_kind(node: Node) -> str | None:
    for ir in node.irs:
        if not isinstance(ir, SolidityCall):
            continue
        name = solidity_call_name(ir)
        if name in ("require(bool)", "require(bool,string)", "require(bool,error)"):
            return "require"
        if name == "assert(bool)":
            return "assert"
    if node.contains_require_or_assert():
        return "require"
    return None


def is_revert_ir(ir: Any) -> bool:
    if not isinstance(ir, SolidityCall):
        return False
    name = solidity_call_name(ir)
    if name in REVERT_NAMES:
        return True
    if isinstance(ir.function, SolidityCustomRevert):
        return True
    return name.startswith("revert ")


def is_revert_node(node: Node) -> bool:
    if node.type == NodeType.THROW:
        return True
    return any(is_revert_ir(ir) for ir in node.irs)


def is_return_node(node: Node) -> bool:
    if node.type == NodeType.RETURN:
        return True
    return any(isinstance(ir, Return) for ir in node.irs)


def callee_of(ir: InternalCall | LibraryCall) -> Function | None:
    fn = ir.function
    if isinstance(fn, Function):
        return fn
    return None


def iter_internal_callees(fn: Function) -> Iterator[tuple[InternalCall | LibraryCall, Function]]:
    for node in fn.nodes:
        for ir in node.irs:
            if isinstance(ir, (InternalCall, LibraryCall)):
                callee = callee_of(ir)
                if callee is None or isinstance(callee, SolidityFunction):
                    continue
                yield ir, callee


def iter_external_calls(node: Node) -> Iterator[HighLevelCall | LowLevelCall]:
    for ir in node.irs:
        if isinstance(ir, LibraryCall):
            continue
        if isinstance(ir, (HighLevelCall, LowLevelCall)):
            yield ir


class FnIR:
    """Per-function def map over non-SSA IR.

    Compound assignments (`m[k] += x`) reuse the Index lvalue as the Binary
    lvalue, so the last def of a REF is not the Index. Keep Index ops separately.
    """

    def __init__(self, function: Function) -> None:
        self.function = function
        self.defs: dict[int, Any] = {}
        self.indexes: dict[int, Index] = {}
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, Index) and ir.lvalue is not None:
                    self.indexes[id(ir.lvalue)] = ir
                if isinstance(ir, OperationWithLValue) and ir.lvalue is not None:
                    self.defs[id(ir.lvalue)] = ir

    def def_of(self, var: Any) -> Any | None:
        return self.defs.get(id(var))

    def index_of(self, var: Any) -> Index | None:
        return self.indexes.get(id(var))

    def unwrap(self, var: Any, *, depth: int = 12) -> Any:
        cur = var
        seen: set[int] = set()
        for _ in range(depth):
            if cur is None or id(cur) in seen:
                return cur
            seen.add(id(cur))
            ir = self.def_of(cur)
            if isinstance(ir, TypeConversion):
                cur = ir.variable
                continue
            if isinstance(ir, Assignment) and not isinstance(ir.rvalue, (Binary, InternalCall, LibraryCall, HighLevelCall)):
                cur = ir.rvalue
                continue
            return cur
        return cur


def fn_ir(function: Function) -> FnIR:
    owner = getattr(function, "contract", None)
    cache = contract_cache(owner, CACHE_FNIR) if owner is not None else None
    if not cache:
        return FnIR(function)
    cached = cache.get(function)
    if cached is None:
        cached = FnIR(function)
        cache[function] = cached
    return cached


def depends(variable: Any, source: Any, context: Function) -> bool:
    if variable is None or source is None:
        return False
    if variable is source or variable == source:
        return True
    try:
        return bool(is_dependent(variable, source, context))
    except Exception:
        return False


def root_state(
    var: Any, function: Function | None = None, _seen: frozenset[int] = frozenset()
) -> StateVariable | None:
    # Non-SSA IR: a local re-assigned from itself (`x = x + ...` lowered through a
    # TMP, or a plain `x = x`) makes the def chain cyclic; `_seen` bounds the walk.
    if var is None or id(var) in _seen:
        return None
    _seen = _seen | {id(var)}
    if isinstance(var, StateVariable):
        return var
    if isinstance(var, ReferenceVariable):
        origin = var.points_to_origin
        if isinstance(origin, StateVariable):
            return origin
        if origin is not var:
            return root_state(origin, function, _seen)
    if function is not None:
        ir = fn_ir(function).def_of(var)
        if isinstance(ir, Index):
            return root_state(ir.variable_left, function, _seen)
        if isinstance(ir, Member):
            return root_state(ir.variable_left, function, _seen)
        if isinstance(ir, TypeConversion):
            return root_state(ir.variable, function, _seen)
        if isinstance(ir, Assignment):
            return root_state(ir.rvalue, function, _seen)
    return None


def index_chain(var: Any, function: Function) -> tuple[StateVariable | None, list[Any]]:
    """Return (root state var, index keys from outer to inner) for Index/Member chains."""
    keys: list[Any] = []
    cur = var
    helper = fn_ir(function)
    seen: set[int] = set()
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, StateVariable):
            return cur, keys
        indexed = helper.index_of(cur)
        ir = indexed if indexed is not None else helper.def_of(cur)
        if isinstance(ir, Index):
            keys.append(ir.variable_right)
            cur = ir.variable_left
            continue
        if isinstance(ir, Member):
            cur = ir.variable_left
            continue
        if isinstance(cur, ReferenceVariable):
            nxt = cur.points_to
            if nxt is None or nxt is cur:
                origin = cur.points_to_origin
                if isinstance(origin, StateVariable):
                    return origin, keys
                break
            cur = nxt
            continue
        break
    origin = root_state(var, function)
    return origin, keys


def reachable_from(start: Node | None, *, banned: Iterable[Node] = ()) -> set[Node]:
    if start is None:
        return set()
    banned_ids = {id(n) for n in banned}
    out: set[Node] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if id(node) in banned_ids or node in out:
            continue
        out.add(node)
        for son in node.sons:
            stack.append(son)
    return out


def ancestors(node: Node, entry: Node | None) -> set[Node]:
    out: set[Node] = set()
    stack = list(node.fathers)
    while stack:
        cur = stack.pop()
        if cur in out:
            continue
        out.add(cur)
        if entry is not None and cur is entry:
            continue
        stack.extend(cur.fathers)
    return out


def if_nodes_on_paths(end: Node, entry: Node | None) -> list[Node]:
    """IF nodes that appear on father-paths from entry to `end` (excluding `end`)."""
    found: list[Node] = []
    seen: set[int] = set()
    for node in ancestors(end, entry):
        if node is end or id(node) in seen:
            continue
        if node.type in (NodeType.IF, NodeType.IFLOOP):
            seen.add(id(node))
            found.append(node)
    found.sort(key=lambda n: (n.source_mapping.start if n.source_mapping else 0, n.node_id))
    return found


def condition_seeds(node: Node) -> list[Any]:
    seeds: list[Any] = []
    for ir in node.irs:
        if isinstance(ir, SolidityCall) and solidity_call_name(ir) in REQUIRE_ASSERT_NAMES:
            if ir.arguments:
                seeds.append(ir.arguments[0])
        elif isinstance(ir, Condition):
            seeds.append(ir.value)
    return seeds


def values_feeding_condition(node: Node) -> list[Any]:
    seeds = condition_seeds(node)
    if not seeds:
        return []
    by_lvalue: dict[int, Any] = {}
    for ir in node.irs:
        if isinstance(ir, OperationWithLValue) and ir.lvalue is not None:
            by_lvalue[id(ir.lvalue)] = ir
    ordered: list[Any] = []
    seen: set[int] = set()
    stack = list(seeds)
    while stack:
        var = stack.pop()
        if var is None:
            continue
        key = id(var)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(var)
        ir = by_lvalue.get(key)
        if ir is None:
            continue
        if isinstance(ir, Unary):
            stack.append(ir.rvalue)
        elif isinstance(ir, Binary):
            stack.append(ir.variable_left)
            stack.append(ir.variable_right)
        elif isinstance(ir, TypeConversion):
            stack.append(ir.variable)
        elif isinstance(ir, Assignment):
            stack.append(ir.rvalue)
        elif isinstance(ir, Index):
            stack.append(ir.variable_left)
            stack.append(ir.variable_right)
        elif isinstance(ir, Member):
            stack.append(ir.variable_left)
        elif isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
            stack.extend(ir.arguments or [])
        elif isinstance(ir, SolidityCall) and solidity_call_name(ir) not in REQUIRE_ASSERT_NAMES:
            # keccak256(answer) == hash: the hashed argument feeds the compare.
            stack.extend(ir.arguments or [])
    return ordered


def _seed_must_be_true(node: Node) -> bool | None:
    """Whether the condition seed must be true for proceed / the IF true-branch."""
    if is_require_assert_node(node):
        return True
    if is_if_node(node):
        true_reverts = branch_reverts_before_write(true_son(node))
        false_reverts = branch_reverts_before_write(false_son(node))
        if true_reverts and not false_reverts:
            return False
        return True
    return None


def bool_needed_true(node: Node, target: Any) -> bool | None:
    """Polarity of `target` in this node's condition.

    True: the function proceeds (or the IF true-branch is taken) iff `target` is true.
    False: iff `target` is false (deny-list / inverted).
    None: `target` does not feed the condition as a bool.
    """
    seed_needed = _seed_must_be_true(node)
    if seed_needed is None or target is None:
        return None
    by_lvalue: dict[int, Any] = {}
    for ir in node.irs:
        if isinstance(ir, OperationWithLValue) and ir.lvalue is not None:
            by_lvalue[id(ir.lvalue)] = ir
    found: bool | None = None
    stack: list[tuple[Any, bool]] = [(seed, seed_needed) for seed in condition_seeds(node)]
    seen: set[tuple[int, bool]] = set()
    while stack:
        var, want = stack.pop()
        if var is None:
            continue
        key = (id(var), want)
        if key in seen:
            continue
        seen.add(key)
        if var is target or id(var) == id(target):
            if found is None:
                found = want
            elif found is not want:
                found = False
        ir = by_lvalue.get(id(var))
        if ir is None:
            continue
        if isinstance(ir, Unary) and ir.type == UnaryType.BANG:
            stack.append((ir.rvalue, not want))
            continue
        if isinstance(ir, Binary):
            if ir.type == BinaryType.ANDAND:
                if want:
                    stack.append((ir.variable_left, want))
                    stack.append((ir.variable_right, want))
                continue
            if ir.type == BinaryType.OROR:
                if not want:
                    stack.append((ir.variable_left, want))
                    stack.append((ir.variable_right, want))
                continue
            if ir.type in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                left, right = ir.variable_left, ir.variable_right
                matched = False
                for side, other in ((left, right), (right, left)):
                    flag = constant_bool(other)
                    if flag is None:
                        continue
                    matched = True
                    if ir.type == BinaryType.EQUAL:
                        stack.append((side, want if flag else (not want)))
                    elif ir.type == BinaryType.NOT_EQUAL:
                        stack.append((side, (not want) if flag else want))
                    else:
                        assert_never(ir.type)
                if not matched:
                    stack.append((left, want))
                    stack.append((right, want))
                continue
            continue
        if isinstance(ir, TypeConversion):
            stack.append((ir.variable, want))
            continue
        if isinstance(ir, Assignment):
            stack.append((ir.rvalue, want))
            continue
        if isinstance(ir, (InternalCall, LibraryCall, Index)):
            continue
    return found


def feeding_irs(node: Node) -> list[Any]:
    feeding_ids = {id(v) for v in values_feeding_condition(node)}
    out: list[Any] = []
    for ir in node.irs:
        if isinstance(ir, OperationWithLValue) and ir.lvalue is not None and id(ir.lvalue) in feeding_ids:
            out.append(ir)
        elif isinstance(ir, (InternalCall, LibraryCall)) and ir.lvalue is not None and id(ir.lvalue) in feeding_ids:
            out.append(ir)
        elif isinstance(ir, SolidityCall) and solidity_call_name(ir) in REQUIRE_ASSERT_NAMES:
            out.append(ir)
        elif isinstance(ir, Condition):
            out.append(ir)
    return out


def path_hits_before_write(
    start: Node | None,
    *,
    pred,
    stop_if_state_write: bool = True,
    extra_stop=None,
) -> bool:
    """True if some path from start hits pred(node) before a state write (and extra_stop)."""
    if start is None:
        return False
    stack: list[tuple[Node, set[int]]] = [(start, set())]
    while stack:
        node, seen = stack.pop()
        if id(node) in seen:
            continue
        seen = seen | {id(node)}
        if extra_stop is not None and extra_stop(node):
            continue
        if pred(node):
            return True
        if stop_if_state_write and node.state_variables_written:
            continue
        for son in node.sons:
            stack.append((son, seen))
    return False


def branch_reverts_before_write(start: Node | None) -> bool:
    return path_hits_before_write(start, pred=is_revert_node)


def branch_returns_before_balance_write(
    start: Node | None, balance_vars: tuple[StateVariable, ...]
) -> bool:
    balance_ids = {id(v) for v in balance_vars}

    def pred(node: Node) -> bool:
        return is_return_node(node)

    def extra(node: Node) -> bool:
        return any(id(v) in balance_ids for v in node.state_variables_written)

    return path_hits_before_write(start, pred=pred, stop_if_state_write=False, extra_stop=extra)


def is_if_node(node: Node) -> bool:
    return node.type in (NodeType.IF, NodeType.IFLOOP)


def true_son(node: Node) -> Node | None:
    return node.son_true if is_if_node(node) else None


def false_son(node: Node) -> Node | None:
    return node.son_false if is_if_node(node) else None


def guarded_nodes(if_node: Node) -> set[Node]:
    """Nodes reachable from the true son that are not reachable from the false son without the IF."""
    true_nodes = reachable_from(true_son(if_node), banned=(if_node,))
    false_nodes = reachable_from(false_son(if_node), banned=(if_node,))
    return true_nodes - false_nodes


def else_guarded_nodes(if_node: Node) -> set[Node]:
    """Nodes reachable only through the false son (the `else` arm)."""
    true_nodes = reachable_from(true_son(if_node), banned=(if_node,))
    false_nodes = reachable_from(false_son(if_node), banned=(if_node,))
    return false_nodes - true_nodes


def guards_of_node(node: Node, function: Function) -> list[Node]:
    """Condition nodes that decide whether `node` executes.

    `if` nodes whose taken arm (either side) exclusively contains `node`, plus
    `require`/`assert` nodes on the father paths from the entry. Unlike end-node
    detection this does not require any arm to revert: a silent `if (ok) pay()` is
    the honeypot shape.
    """
    entry = function.entry_point
    above = ancestors(node, entry)
    out: list[Node] = []
    for cand in function.nodes:
        if cand is node:
            continue
        if is_if_node(cand) and cand.type == NodeType.IF:
            if node in guarded_nodes(cand) or node in else_guarded_nodes(cand):
                out.append(cand)
        elif is_require_assert_node(cand) and cand in above:
            out.append(cand)
    return sorted_nodes(out)


def sender_literal_source(var: Any, helper: FnIR) -> str | None:
    cur = helper.unwrap(var)
    if is_msg_sender(cur) or is_msg_sender(var):
        return "msg.sender"
    if is_tx_origin(cur) or is_tx_origin(var):
        return "tx.origin"
    return None


def returns_sender_source(fn: Function) -> str | None:
    for rv in fn.return_values or []:
        if is_msg_sender(rv):
            return "msg.sender"
        if is_tx_origin(rv):
            return "tx.origin"
    for node in fn.nodes:
        for ir in node.irs:
            if not isinstance(ir, Return):
                continue
            for val in ir.values:
                helper = fn_ir(fn)
                src = sender_literal_source(val, helper)
                if src is not None:
                    return src
    return None


def returns_state_addresses(fn: Function) -> list[StateVariable]:
    found: list[StateVariable] = []
    seen: set[int] = set()

    def add(var: Any) -> None:
        if isinstance(var, StateVariable) and is_address_var(var) and id(var) not in seen:
            seen.add(id(var))
            found.append(var)

    for rv in fn.return_values or []:
        add(rv)
        add(root_state(rv, fn))
    for node in fn.nodes:
        for ir in node.irs:
            if isinstance(ir, Return):
                for val in ir.values:
                    add(val)
                    add(root_state(val, fn))
                    if depends(val, val, fn):
                        for sv in sorted_vars(fn.state_variables_read):
                            if is_address_var(sv) and depends(val, sv, fn):
                                add(sv)
    return found


def is_this_expr(var: Any, function: Function) -> bool:
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if is_this(cur) or is_this(var):
        return True
    ir = helper.def_of(var)
    if isinstance(ir, TypeConversion) and is_this(helper.unwrap(ir.variable)):
        return True
    return False


def resolve_state_dest(var: Any, function: Function) -> StateVariable | None:
    helper = fn_ir(function)
    cur: Any = var
    seen: set[int] = set()
    for _ in range(16):
        if cur is None or id(cur) in seen:
            break
        seen.add(id(cur))
        if isinstance(cur, StateVariable):
            return cur
        if isinstance(cur, ReferenceVariable):
            origin = cur.points_to_origin
            if isinstance(origin, StateVariable):
                return origin
            cur = origin
            continue
        ir = helper.def_of(cur)
        if isinstance(ir, TypeConversion):
            cur = ir.variable
            continue
        if isinstance(ir, Assignment):
            cur = ir.rvalue
            continue
        break
    for sv in sorted_vars(function.state_variables_read):
        if depends(var, sv, function):
            return sv
    contract = getattr(function, "contract", None)
    if contract is not None:
        for sv in sorted_vars(contract.state_variables):
            if depends(var, sv, function):
                return sv
    return None


def is_whole_pot_value(value_var: Any, function: Function) -> bool:
    if value_var is None:
        return False
    helper = fn_ir(function)
    cur = value_var
    seen: set[int] = set()
    for _ in range(12):
        if cur is None or id(cur) in seen:
            break
        seen.add(id(cur))
        if isinstance(cur, SolidityVariableComposed) and cur.name in ("this.balance", "self.balance"):
            return True
        ir = helper.def_of(cur)
        if isinstance(ir, SolidityCall) and solidity_call_name(ir) in BALANCE_CALL_NAMES:
            args = ir.arguments or []
            if args and is_this_expr(args[0], function):
                return True
        if isinstance(ir, Member) and str(ir.variable_right) == "balance":
            if is_this_expr(ir.variable_left, function):
                return True
        if isinstance(ir, TypeConversion):
            cur = ir.variable
            continue
        if isinstance(ir, Assignment):
            cur = ir.rvalue
            continue
        break
    return False


def pot_dependent(value_var: Any, function: Function, *, depth: int = 10) -> bool:
    """`address(this).balance` feeds the value through arithmetic / copies / arith helpers.

    `is_whole_pot_value` is the exact whole-pot test; this is the wider
    data-dependence (`this.balance + msg.value`, `this.balance.mul(x).div(y)`).
    """
    helper = fn_ir(function)
    stack: list[tuple[Any, int]] = [(value_var, depth)]
    seen: set[int] = set()
    while stack:
        cur, left = stack.pop()
        if cur is None or left <= 0 or id(cur) in seen:
            continue
        seen.add(id(cur))
        if is_whole_pot_value(cur, function):
            return True
        ir = helper.def_of(cur)
        if isinstance(ir, Binary):
            stack.append((ir.variable_left, left - 1))
            stack.append((ir.variable_right, left - 1))
        elif isinstance(ir, TypeConversion):
            stack.append((ir.variable, left - 1))
        elif isinstance(ir, Assignment):
            stack.append((ir.rvalue, left - 1))
        elif isinstance(ir, (InternalCall, LibraryCall)):
            for arg in ir.arguments or []:
                stack.append((arg, left - 1))
    return False


def assembly_has_delegatecall(node: Node) -> bool:
    if node.type not in (NodeType.ASSEMBLY, NodeType.ENDASSEMBLY):
        return False
    mapping = node.source_mapping
    content = ""
    if mapping is not None:
        content = mapping.content or ""
    expr = str(node.expression) if node.expression is not None else ""
    blob = f"{content}\n{expr}"
    return "delegatecall(" in blob.replace(" ", "")


def call_full_name(ir: HighLevelCall) -> str:
    fn = ir.function
    if isinstance(fn, Function):
        return solidity_sig(fn)
    name = str(ir.function_name) if ir.function_name is not None else ""
    if isinstance(fn, Variable):
        return getattr(fn, "full_name", None) or name
    return getattr(fn, "full_name", None) or name


def closure_with_zero_params(function: Function) -> list[tuple[Function, frozenset[int]]]:
    """Internal-call closure with parameters bound to address(0) on every path from `function`."""

    def argument_is_zero(arg: Any, caller: Function, zero_param_ids: frozenset[int]) -> bool:
        if arg is None:
            return False
        if id(arg) in zero_param_ids:
            return True
        if isinstance(arg, Constant):
            val = arg.value
            return val == 0 or val is False
        helper = fn_ir(caller)
        unwrapped = helper.unwrap(arg)
        for param in caller.parameters or []:
            if (arg is param or unwrapped is param) and id(param) in zero_param_ids:
                return True
        ir = helper.def_of(arg)
        if isinstance(ir, TypeConversion):
            inner = ir.variable
            if isinstance(inner, Constant):
                val = inner.value
                return val == 0 or val is False
        return False

    zeros: dict[int, frozenset[int]] = {id(function): frozenset()}
    seen_fns: dict[int, Function] = {id(function): function}
    work = [function]
    while work:
        current = work.pop()
        current_zeros = zeros[id(current)]
        for ir, callee in iter_internal_callees(current):
            args = list(ir.arguments or [])
            params = list(callee.parameters or [])
            edge_ids: list[int] = []
            if len(args) == len(params):
                for arg, param in zip(args, params):
                    if argument_is_zero(arg, current, current_zeros):
                        edge_ids.append(id(param))
            edge_zeros = frozenset(edge_ids)
            cid = id(callee)
            if cid not in zeros:
                zeros[cid] = edge_zeros
                seen_fns[cid] = callee
                work.append(callee)
                continue
            merged = zeros[cid] & edge_zeros
            if merged != zeros[cid]:
                zeros[cid] = merged
                work.append(callee)
    items = [(fn, zeros[id(fn)]) for fn in seen_fns.values()]
    items.sort(key=lambda item: function_sort_key(item[0]))
    return items
