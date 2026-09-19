"""Name-agnostic privilege predicates (research §5 predicate 1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from slither.core.cfg.node import Node, NodeType
from slither.core.declarations.function import Function
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable
from slither.slithir.operations import (
    Binary,
    Index,
    InternalCall,
    LibraryCall,
    Return,
)
from slither.slithir.operations.binary import BinaryType
from slither.slithir.variables.reference import ReferenceVariable

from detector.analysis._ir import (
    CACHE_AUTH,
    CACHE_BRANCH,
    CACHE_PRIV,
    MSG_SENDER,
    TX_ORIGIN,
    assert_never,
    bool_needed_true,
    branch_reverts_before_write,
    callee_of,
    constant_bool,
    contract_cache,
    depends,
    else_guarded_nodes,
    false_son,
    feeding_irs,
    fn_ir,
    function_sort_key,
    guarded_nodes,
    index_chain,
    is_address_var,
    is_bool_type,
    is_ctor,
    is_externally_callable,
    is_if_node,
    is_modifier,
    is_msg_value,
    is_require_assert_node,
    iter_internal_callees,
    mapping_leaf_type,
    node_sort_key,
    returns_sender_source,
    returns_state_addresses,
    root_state,
    sender_literal_source,
    sorted_nodes,
    sorted_vars,
    true_son,
    unique_functions,
    values_feeding_condition,
    var_sort_key,
)

AuthKind = Literal["eq_state_address", "map_bool", "tx_origin"]
SenderSource = Literal["msg.sender", "tx.origin"]
WriteMode = Literal["function", "branch"]

_EQ_TYPES = (BinaryType.EQUAL, BinaryType.NOT_EQUAL)


@dataclass(frozen=True)
class AuthAtom:
    node: Node
    kind: AuthKind
    auth_var: StateVariable
    sender_source: SenderSource


@dataclass(frozen=True)
class PrivilegedWrite:
    var: StateVariable
    function: Function
    node: Node
    auth_vars: tuple[StateVariable, ...]
    mode: WriteMode


def _taint_key(taint: dict[Variable, str]) -> tuple[tuple[int, str], ...]:
    return tuple(sorted((id(var), src) for var, src in taint.items()))


def _is_function_param(var: Any, function: Function, helper: Any) -> bool:
    params = list(function.parameters or [])
    if not params:
        return False
    if var in params:
        return True
    unwrapped = helper.unwrap(var)
    return unwrapped in params


def _sender_source_of(
    var: Any,
    function: Function,
    taint: dict[Variable, str],
) -> str | None:
    helper = fn_ir(function)
    literal = sender_literal_source(var, helper)
    if literal is not None:
        return literal
    unwrapped = helper.unwrap(var)
    if unwrapped in taint:
        return taint[unwrapped]
    if var in taint:
        return taint[var]
    for tainted, src in sorted(taint.items(), key=lambda item: var_sort_key(item[0])):
        if var is tainted or unwrapped is tainted:
            return src
        if _is_function_param(var, function, helper):
            continue
        if depends(var, tainted, function) or depends(unwrapped, tainted, function):
            return src
    ir = helper.def_of(var)
    if isinstance(ir, (InternalCall, LibraryCall)):
        callee = callee_of(ir)
        if callee is not None:
            got = returns_sender_source(callee)
            if got is not None:
                return got
    # Slither's is_dependent is interprocedural: `_transfer.from` is marked
    # dependent on msg.sender because `transfer` passes msg.sender. Parameters
    # are sender-tainted only via explicit call-site taint (non-writing helpers).
    if _is_function_param(var, function, helper):
        return None
    if depends(var, MSG_SENDER, function) or depends(unwrapped, MSG_SENDER, function):
        return "msg.sender"
    if depends(var, TX_ORIGIN, function) or depends(unwrapped, TX_ORIGIN, function):
        return "tx.origin"
    return None


def _normalize_sender(src: str | None) -> SenderSource | None:
    if src == "msg.sender":
        return "msg.sender"
    if src == "tx.origin":
        return "tx.origin"
    if src is None:
        return None
    assert_never(src)
    return None


def _kind_for_compare(sender_source: SenderSource) -> AuthKind:
    if sender_source == "tx.origin":
        return "tx_origin"
    if sender_source == "msg.sender":
        return "eq_state_address"
    assert_never(sender_source)
    return "eq_state_address"


def _leaf_is_bool(var: Any) -> bool:
    return is_bool_type(getattr(var, "type", None))


def _map_bool_root(
    var: Any,
    function: Function,
    taint: dict[Variable, str],
) -> tuple[StateVariable, SenderSource] | None:
    root, keys = index_chain(var, function)
    if root is None or not keys:
        return None
    if not _leaf_is_bool(var) and not is_bool_type(mapping_leaf_type(root.type)):
        return None
    if not _leaf_is_bool(var) and not is_bool_type(getattr(var, "type", None)):
        # Nested struct member may carry mapping(address=>bool); accept if any key is address-like
        # and the IR result type is bool.
        if not is_bool_type(getattr(var, "type", None)):
            return None
    for key in keys:
        src = _normalize_sender(_sender_source_of(key, function, taint))
        if src is not None:
            return root, src
    return None


def _state_address_from_value(
    var: Any,
    function: Function,
) -> StateVariable | None:
    helper = fn_ir(function)
    cur = helper.unwrap(var)
    if isinstance(cur, StateVariable) and is_address_var(cur):
        return cur
    if isinstance(var, StateVariable) and is_address_var(var):
        return var
    ir = helper.def_of(var)
    if isinstance(ir, (InternalCall, LibraryCall)):
        callee = callee_of(ir)
        if callee is None:
            return None
        addrs = returns_state_addresses(callee)
        if len(addrs) == 1:
            return addrs[0]
        # owner() shape: return depends on exactly one state address.
        addr_deps = [sv for sv in callee.state_variables_read if is_address_var(sv)]
        if len(addr_deps) == 1:
            return addr_deps[0]
    root = root_state(cur, function)
    if isinstance(root, StateVariable) and is_address_var(root):
        return root
    return None


def _arg_taint_for_callee(
    ir: InternalCall | LibraryCall,
    caller: Function,
    taint: dict[Variable, str],
    callee: Function,
) -> dict[Variable, str]:
    new_taint: dict[Variable, str] = {}
    args = list(ir.arguments or [])
    params = list(callee.parameters or [])
    writes_state = bool(callee.state_variables_written) or bool(callee.all_state_variables_written())
    helper_callee = callee.view or callee.pure or is_modifier(callee) or not writes_state
    if not helper_callee:
        return new_taint
    for idx, param in enumerate(params):
        if idx >= len(args):
            break
        src = _normalize_sender(_sender_source_of(args[idx], caller, taint))
        if src is None:
            continue
        new_taint[param] = src
    return new_taint


def _atoms_from_call_return(
    ir: InternalCall | LibraryCall,
    node: Node,
    function: Function,
    taint: dict[Variable, str],
) -> list[AuthAtom]:
    callee = callee_of(ir)
    if callee is None:
        return []
    if ir.lvalue is None or bool_needed_true(node, ir.lvalue) is not True:
        return []
    call_taint = _arg_taint_for_callee(ir, function, taint, callee)
    atoms: list[AuthAtom] = []
    addrs = returns_state_addresses(callee)
    sender = _normalize_sender(_sender_source_of(ir.lvalue, function, taint))
    # Compare uses the call result as one operand; handled at Binary. Here: map_bool view.
    for rv in callee.return_values or []:
        mapped = _map_bool_root(rv, callee, call_taint)
        if mapped is not None:
            root, src = mapped
            kind: AuthKind = "tx_origin" if src == "tx.origin" else "map_bool"
            if kind == "tx_origin":
                atoms.append(AuthAtom(node, "tx_origin", root, "tx.origin"))
            elif kind == "map_bool":
                atoms.append(AuthAtom(node, "map_bool", root, src))
            else:
                assert_never(kind)
    if not atoms:
        for node_c in callee.nodes:
            for ret in node_c.irs:
                if not isinstance(ret, Return):
                    continue
                for val in ret.values:
                    mapped = _map_bool_root(val, callee, call_taint)
                    if mapped is None:
                        continue
                    root, src = mapped
                    if src == "tx.origin":
                        atoms.append(AuthAtom(node, "tx_origin", root, "tx.origin"))
                    elif src == "msg.sender":
                        atoms.append(AuthAtom(node, "map_bool", root, "msg.sender"))
                    else:
                        assert_never(src)
    if not atoms:
        atoms.extend(_bool_helper_atoms(callee, node, call_taint))
    if not atoms:
        atoms.extend(_membership_call_atoms(callee, node, call_taint))
    _ = sender
    _ = addrs
    return atoms


def _membership_call_atoms(
    callee: Function, call_node: Node, call_taint: dict[Variable, str]
) -> list[AuthAtom]:
    """`hasRole(role, account)` over a set library: the callee returns the bool of a
    non-writing library / internal call whose arguments are the sender (tainted param)
    and a reference rooted at a state variable (`_roles[role].members.contains(account)`).
    Set membership keyed by the sender is a `map_bool` gate, whatever the set type."""
    helper = fn_ir(callee)
    atoms: list[AuthAtom] = []
    for node in callee.nodes:
        for ret in node.irs:
            if not isinstance(ret, Return):
                continue
            for val in ret.values:
                ir = helper.def_of(val)
                if not isinstance(ir, (InternalCall, LibraryCall)) or not _leaf_is_bool(ir.lvalue):
                    continue
                inner = callee_of(ir)
                if inner is None or inner.state_variables_written or inner.all_state_variables_written():
                    continue
                args = list(ir.arguments or [])
                sources = [_normalize_sender(_sender_source_of(arg, callee, call_taint)) for arg in args]
                roots = [root_state(arg, callee) for arg in args]
                for i, src in enumerate(sources):
                    if src is None:
                        continue
                    for j, root in enumerate(roots):
                        if i == j or root is None:
                            continue
                        kind: AuthKind = "tx_origin" if src == "tx.origin" else "map_bool"
                        atoms.append(AuthAtom(call_node, kind, root, src))
    return atoms


def _eq_compare_atoms(
    irs: list[Any], node: Node, function: Function, taint: dict[Variable, str]
) -> list[AuthAtom]:
    """`msg.sender ==/!= <state address>` compares among `irs`, attributed to `node`."""
    atoms: list[AuthAtom] = []
    for ir in irs:
        if not isinstance(ir, Binary) or ir.type not in _EQ_TYPES:
            continue
        left, right = ir.variable_left, ir.variable_right
        for sender_side, other in ((left, right), (right, left)):
            src = _normalize_sender(_sender_source_of(sender_side, function, taint))
            if src is None:
                continue
            auth = _state_address_from_value(other, function)
            if auth is None:
                continue
            atoms.append(AuthAtom(node, _kind_for_compare(src), auth, src))
    return atoms


def _returns_true_literal(nodes: set[Node]) -> bool:
    for node in nodes:
        for ir in node.irs:
            if isinstance(ir, Return) and any(constant_bool(val) is True for val in ir.values):
                return True
    return False


def _bool_helper_atoms(
    callee: Function, call_node: Node, call_taint: dict[Variable, str]
) -> list[AuthAtom]:
    """`isOwner()`-style helpers: a state-free callee whose `true` result requires a
    sender compare — `return Owner == msg.sender;` or `if (Owner == msg.sender) return true;`."""
    if callee.state_variables_written or callee.all_state_variables_written():
        return []
    atoms: list[AuthAtom] = []
    for node in callee.nodes:
        if any(isinstance(ir, Return) for ir in node.irs):
            atoms.extend(_eq_compare_atoms(list(node.irs), call_node, callee, call_taint))
        if is_if_node(node) and _returns_true_literal(guarded_nodes(node)):
            found = _eq_compare_atoms(list(node.irs), call_node, callee, call_taint)
            atoms.extend(found)
    return atoms


def _atoms_in_node(node: Node, function: Function, taint: dict[Variable, str]) -> list[AuthAtom]:
    atoms: list[AuthAtom] = []
    seen: set[tuple[str, int, str]] = set()

    def add(atom: AuthAtom) -> None:
        key = (atom.kind, id(atom.auth_var), atom.sender_source)
        if key in seen:
            return
        seen.add(key)
        atoms.append(atom)

    feeding = values_feeding_condition(node)
    if not feeding and not (is_require_assert_node(node) or is_if_node(node)):
        return atoms

    for atom in _eq_compare_atoms(feeding_irs(node) + list(node.irs), node, function, taint):
        add(atom)
    for ir in feeding_irs(node) + list(node.irs):
        if isinstance(ir, Index) and ir.lvalue is not None:
            mapped = _map_bool_root(ir.lvalue, function, taint)
            if mapped is not None and bool_needed_true(node, ir.lvalue) is True:
                root, src = mapped
                if src == "tx.origin":
                    add(AuthAtom(node, "tx_origin", root, "tx.origin"))
                elif src == "msg.sender":
                    add(AuthAtom(node, "map_bool", root, "msg.sender"))
                else:
                    assert_never(src)
        if isinstance(ir, (InternalCall, LibraryCall)):
            for atom in _atoms_from_call_return(ir, node, function, taint):
                add(atom)

    # Direct require(mapping[sender]) where the Index lvalue is the require argument.
    for val in feeding:
        if isinstance(val, (ReferenceVariable, StateVariable)):
            mapped = _map_bool_root(val, function, taint)
            if mapped is not None and bool_needed_true(node, val) is True:
                root, src = mapped
                if src == "tx.origin":
                    add(AuthAtom(node, "tx_origin", root, "tx.origin"))
                elif src == "msg.sender":
                    add(AuthAtom(node, "map_bool", root, "msg.sender"))
                else:
                    assert_never(src)
        src = _normalize_sender(_sender_source_of(val, function, taint))
        auth = _state_address_from_value(val, function)
        # A bare state address in a condition is not an atom without a compare.
        _ = src
        _ = auth
    return atoms


def _guards_placeholder(node: Node) -> bool:
    """Modifier `if (cond) _;` — the body runs only inside the taken arm (silent auth)."""
    owner = node.function
    if owner is None or not is_modifier(owner):
        return False
    return any(son.type == NodeType.PLACEHOLDER for son in guarded_nodes(node))


def _is_end_auth_node(node: Node) -> bool:
    if is_require_assert_node(node):
        return True
    if is_if_node(node):
        if branch_reverts(node):
            return True
        if _guards_placeholder(node):
            return True
    return False


def branch_reverts(node: Node) -> bool:
    return branch_reverts_before_write(true_son(node)) or branch_reverts_before_write(false_son(node))


def _walk_auth(
    function: Function,
    taint: dict[Variable, str],
    seen: set[tuple[int, tuple[tuple[int, str], ...]]],
    into: list[AuthAtom],
    *,
    end_only: bool,
) -> None:
    key = (id(function), _taint_key(taint))
    if key in seen:
        return
    seen.add(key)
    for node in function.nodes:
        if end_only:
            if not _is_end_auth_node(node):
                continue
            into.extend(_atoms_in_node(node, function, taint))
        else:
            if is_if_node(node) and not _is_end_auth_node(node):
                for atom in _atoms_in_node(node, function, taint):
                    into.append(atom)
    for mod in function.modifiers:
        if isinstance(mod, Function):
            _walk_auth(mod, {}, seen, into, end_only=end_only)
    for ir, callee in iter_internal_callees(function):
        if is_ctor(callee):
            continue
        new_taint = _arg_taint_for_callee(ir, function, taint, callee)
        _walk_auth(callee, new_taint, seen, into, end_only=end_only)


def _fn_cache(function: Function, attr: str) -> dict | None:
    owner = getattr(function, "contract", None)
    if owner is None:
        return None
    return contract_cache(owner, attr)


def auth_atoms(function: Function) -> list[AuthAtom]:
    if is_ctor(function):
        return []
    cache = _fn_cache(function, CACHE_AUTH)
    if cache is not None:
        cached = cache.get(function)
        if cached is not None:
            return cached
    atoms: list[AuthAtom] = []
    _walk_auth(function, {}, set(), atoms, end_only=True)
    if cache is not None:
        cache[function] = atoms
    return atoms


def branch_atoms(function: Function) -> list[tuple[AuthAtom, Node]]:
    if is_ctor(function):
        return []
    cache = _fn_cache(function, CACHE_BRANCH)
    if cache is not None:
        cached = cache.get(function)
        if cached is not None:
            return cached
    out: list[tuple[AuthAtom, Node]] = []
    for node in function.nodes:
        if not is_if_node(node):
            continue
        if _is_end_auth_node(node):
            continue
        for atom in _atoms_in_node(node, function, {}):
            out.append((atom, node))
    if cache is not None:
        cache[function] = out
    return out


def is_privileged(function: Function) -> bool:
    if is_ctor(function):
        return False
    return bool(auth_atoms(function))


def _auth_vars_of(function: Function) -> tuple[StateVariable, ...]:
    atoms = auth_atoms(function)
    seen: list[StateVariable] = []
    ids: set[int] = set()
    for atom in atoms:
        if id(atom.auth_var) not in ids:
            ids.add(id(atom.auth_var))
            seen.append(atom.auth_var)
    return tuple(seen)


def _write_sites(function: Function, seen: set[int] | None = None) -> list[tuple[Node, StateVariable]]:
    if seen is None:
        seen = set()
    if id(function) in seen:
        return []
    seen.add(id(function))
    sites: list[tuple[Node, StateVariable]] = []
    for node in function.nodes:
        for var in sorted_vars(node.state_variables_written):
            sites.append((node, var))
    for _, callee in iter_internal_callees(function):
        if is_modifier(callee) or is_ctor(callee):
            continue
        sites.extend(_write_sites(callee, seen))
    return sites


def privileged_writes(contract: Any) -> list[PrivilegedWrite]:
    cached = getattr(contract, CACHE_PRIV, None)
    if cached is not None:
        return cached
    out: list[PrivilegedWrite] = []
    seen_keys: set[tuple[int, int, int, str]] = set()
    for fn in unique_functions(contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if is_privileged(fn):
            auth = _auth_vars_of(fn)
            for node, var in _write_sites(fn):
                key = (id(var), id(fn), id(node), "function")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                out.append(PrivilegedWrite(var, fn, node, auth, "function"))
            continue
        for atom, if_node in branch_atoms(fn):
            guarded = guarded_nodes(if_node)
            for node in sorted_nodes(guarded):
                for var in sorted_vars(node.state_variables_written):
                    key = (id(var), id(fn), id(node), "branch")
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    out.append(
                        PrivilegedWrite(var, fn, node, (atom.auth_var,), "branch")
                    )
    out.sort(
        key=lambda pw: (
            var_sort_key(pw.var),
            function_sort_key(pw.function),
            node_sort_key(pw.node),
            pw.mode,
        )
    )
    try:
        setattr(contract, CACHE_PRIV, out)
    except Exception:
        pass
    return out


def _node_in_privileged_branch(function: Function, node: Node) -> bool:
    for _, if_node in branch_atoms(function):
        if node in guarded_nodes(if_node):
            return True
    return False


def unprivileged_writers(contract: Any, var: StateVariable) -> list[Function]:
    writers: list[Function] = []
    seen: set[int] = set()
    for fn in unique_functions(contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if not is_externally_callable(fn):
            continue
        if is_privileged(fn):
            continue
        wrote = False
        for node, written in _write_sites(fn):
            if written is not var:
                continue
            owner = node.function
            if _node_in_privileged_branch(fn, node):
                continue
            if owner is not None and _node_in_privileged_branch(owner, node):
                continue
            wrote = True
            break
        if wrote and id(fn) not in seen:
            seen.add(id(fn))
            writers.append(fn)
    return writers


def privileged_writable(contract: Any) -> dict[StateVariable, list[PrivilegedWrite]]:
    grouped: dict[int, list[PrivilegedWrite]] = {}
    vars_by_id: dict[int, StateVariable] = {}
    for pw in privileged_writes(contract):
        if pw.var.is_constant or pw.var.is_immutable:
            continue
        grouped.setdefault(id(pw.var), []).append(pw)
        vars_by_id[id(pw.var)] = pw.var
    out: dict[StateVariable, list[PrivilegedWrite]] = {}
    for vid, writes in grouped.items():
        var = vars_by_id[vid]
        if unprivileged_writers(contract, var):
            continue
        out[var] = writes
    return dict(sorted(out.items(), key=lambda item: var_sort_key(item[0])))


def auth_vars(contract: Any) -> set[StateVariable]:
    found: set[StateVariable] = set()
    for fn in unique_functions(contract):
        if is_ctor(fn):
            continue
        for atom in auth_atoms(fn):
            found.add(atom.auth_var)
        for atom, _ in branch_atoms(fn):
            found.add(atom.auth_var)
    return found


def is_exposed(contract: Any, var: StateVariable) -> bool:
    if var.visibility == "public":
        return True
    for fn in unique_functions(contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if not is_externally_callable(fn):
            continue
        if not (fn.view or fn.pure):
            continue
        for rv in fn.return_values or []:
            if rv is var or root_state(rv, fn) is var or depends(rv, var, fn):
                return True
        for node in fn.nodes:
            for ir in node.irs:
                if not isinstance(ir, Return):
                    continue
                for val in ir.values:
                    if val is var or root_state(val, fn) is var or depends(val, var, fn):
                        return True
    return False


def role_writers(contract: Any, var: StateVariable) -> list[Function]:
    writers: list[Function] = []
    for fn in unique_functions(contract):
        if is_ctor(fn) or is_modifier(fn):
            continue
        if var in fn.state_variables_written or var in fn.all_state_variables_written():
            writers.append(fn)
    return writers


def node_silently_gated_by_state(node: Node) -> bool:
    """`node` runs only inside an `if` arm whose condition reads state or `msg.value`.

    The arm is a silent skip (no revert): `if (hash == 0x0 || msg.value > 1 ether) hash = h;`
    is the HoneyBadger writer shape — the depositor's call succeeds but changes nothing.
    """
    function = node.function
    if function is None:
        return False
    for cand in function.nodes:
        if not is_if_node(cand) or cand.type != NodeType.IF:
            continue
        if node not in guarded_nodes(cand) and node not in else_guarded_nodes(cand):
            continue
        if branch_reverts(cand):
            continue
        if cand.state_variables_read:
            return True
        if any(is_msg_value(val) for val in values_feeding_condition(cand)):
            return True
    return False


def depositor_locked(contract: Any, var: StateVariable) -> bool:
    """Every post-constructor write of `var` is privileged or silently state-gated.

    A state var the payout guard compares against is "practically unwritable" by a
    depositor when each externally reachable writer either carries an auth atom or
    performs the write only inside a non-reverting `if` arm that reads state /
    `msg.value` (`SetPass`, `StartRoulette` shapes). Constants and vars with no
    post-constructor writer are trivially locked.
    """
    if var.is_constant or var.is_immutable:
        return True
    for fn in unique_functions(contract):
        if is_ctor(fn) or is_modifier(fn) or not is_externally_callable(fn):
            continue
        sites = [node for node, written in _write_sites(fn) if written is var]
        if not sites:
            continue
        if is_privileged(fn):
            continue
        for node in sites:
            if _node_in_privileged_branch(fn, node):
                continue
            owner = node.function
            if owner is not None and owner is not fn and _node_in_privileged_branch(owner, node):
                continue
            if node_silently_gated_by_state(node):
                continue
            return False
    return True


def bait_writer_exists(contract: Any, var: StateVariable) -> bool:
    """A non-privileged **payable** function writes `var` only inside a silent state-gated
    arm: "pay to become the receiver" — the deposit succeeds, the write silently does not."""
    for fn in unique_functions(contract):
        if is_ctor(fn) or is_modifier(fn) or not is_externally_callable(fn):
            continue
        if not fn.payable or is_privileged(fn):
            continue
        for node, written in _write_sites(fn):
            if written is var and node_silently_gated_by_state(node):
                return True
    return False


def shadowed_auth_vars(contract: Any) -> list[tuple[StateVariable, StateVariable]]:
    """(auth_var, shadow) pairs: a state var of the same name declared elsewhere in the
    inheritance chain (HoneyBadger inheritance disorder — the derived `owner` never
    reaches the base modifier). Structural name collision, not a word list."""
    ordered = list(getattr(contract, "state_variables_ordered", None) or contract.state_variables)
    out: list[tuple[StateVariable, StateVariable]] = []
    for auth in sorted_vars(auth_vars(contract)):
        for other in ordered:
            if other is auth or other.name != auth.name:
                continue
            out.append((auth, other))
    return out
