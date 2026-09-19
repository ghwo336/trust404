"""Family E: structural escape hatches (external gates, delegatecall, proxy, selfdestruct)."""

from __future__ import annotations

from typing import Any

from slither.core.declarations.function import Function
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import LowLevelCall, SolidityCall

from detector.analysis._ir import (
    SELFDESTRUCT_NAMES,
    assembly_has_delegatecall,
    depends,
    function_sort_key,
    guarded_nodes,
    is_address_var,
    is_ctor,
    is_externally_callable,
    is_modifier,
    iter_internal_callees,
    resolve_state_dest,
    solidity_call_name,
    unique_functions,
)
from detector.analysis.context import ContractContext
from detector.analysis.flows import value_sends
from detector.analysis.privilege import auth_atoms, branch_atoms, is_privileged
from detector.model import Finding
from detector.rules.base import make_finding

_MSG_DATA = SolidityVariableComposed("msg.data")


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


def _blob(function: Function) -> str:
    parts: list[str] = []
    for node in function.nodes:
        mapping = getattr(node, "source_mapping", None)
        if mapping is not None and mapping.content:
            parts.append(mapping.content)
        if node.expression is not None:
            parts.append(str(node.expression))
    return "".join(parts).replace(" ", "")


def _forwards_calldata(function: Function) -> bool:
    blob = _blob(function)
    if "calldatacopy(" in blob or "calldatasize(" in blob:
        return True
    return "msg.data" in blob


def _is_delegatecall_ir(ir: Any) -> bool:
    if isinstance(ir, LowLevelCall):
        name = str(ir.function_name) if ir.function_name is not None else ""
        return name == "delegatecall"
    if isinstance(ir, SolidityCall):
        return "delegatecall" in solidity_call_name(ir)
    return False


def _has_delegatecall(function: Function) -> bool:
    for node in function.nodes:
        if assembly_has_delegatecall(node):
            return True
        for ir in node.irs:
            if _is_delegatecall_ir(ir):
                return True
    return False


def _is_proxy_fallback(function: Function) -> bool:
    if not function.is_fallback:
        return False
    return _has_delegatecall(function) and _forwards_calldata(function)


def _privileged_delegatecall_site(function: Function, node: Any) -> bool:
    if is_privileged(function):
        return True
    if node is None:
        return False
    for _atom, if_node in branch_atoms(function):
        if node in guarded_nodes(if_node):
            return True
    return False


def _dest_depends_on_param_or_calldata(dest: Any, function: Function) -> bool:
    if dest is None:
        return False
    for param in function.parameters or []:
        if depends(dest, param, function):
            return True
    return depends(dest, _MSG_DATA, function)


def _pw_addrs_read(function: Function, ctx: ContractContext) -> list[StateVariable]:
    found: list[StateVariable] = []
    seen: set[int] = set()
    for var in function.state_variables_read:
        if var not in ctx.privileged_writable:
            continue
        if not is_address_var(var):
            continue
        if id(var) in seen:
            continue
        seen.add(id(var))
        found.append(var)
    return found


def _single_addr_admin(function: Function) -> bool:
    atoms = auth_atoms(function)
    return bool(atoms) and all(atom.kind == "eq_state_address" for atom in atoms)


def _externally_reachable(ctx: ContractContext, target: Function) -> bool:
    if is_externally_callable(target) and target.is_implemented:
        return True
    stack = [fn for fn in unique_functions(ctx.contract) if is_externally_callable(fn) and fn.is_implemented]
    seen: set[int] = set()
    while stack:
        fn = stack.pop()
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        if fn is target:
            return True
        for _, callee in iter_internal_callees(fn):
            stack.append(callee)
    return False


def _selfdestruct_node(function: Function) -> Any | None:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall) and solidity_call_name(ir) in SELFDESTRUCT_NAMES:
                return node
    for node, _to, _value, kind in value_sends(function):
        if kind == "selfdestruct":
            return node
    return None


def struct_external_gate(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()
    for function, node, target in ctx.external_calls_on_path:
        if target is None:
            continue
        if target.is_constant or target.is_immutable:
            continue
        if target not in ctx.privileged_writable:
            continue
        writers = ctx.privileged_writable[target]
        writer_names = ", ".join(pw.function.name for pw in writers) or "?"
        item = _emit(
            "STRUCT_EXTERNAL_GATE",
            ctx,
            function,
            node,
            f"{function.name} calls through privileged-writable {target.name} (writers: {writer_names})",
        )
        key = (item.function, item.lines)
        if key in seen:
            continue
        seen.add(key)
        findings.append(item)
    return findings


def struct_delegatecall_settable(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    def add(item: Finding) -> None:
        key = (item.function, item.lines)
        if key in seen:
            return
        seen.add(key)
        findings.append(item)

    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        if _is_proxy_fallback(function):
            continue
        dests: list[tuple[Any, StateVariable]] = []
        param_nodes: list[Any] = []
        for node in function.nodes:
            for ir in node.irs:
                if not isinstance(ir, LowLevelCall):
                    continue
                if not _is_delegatecall_ir(ir):
                    continue
                dest = resolve_state_dest(ir.destination, function)
                if dest is not None:
                    dests.append((node, dest))
                if _privileged_delegatecall_site(function, node) and _dest_depends_on_param_or_calldata(
                    ir.destination, function
                ):
                    param_nodes.append(node)
            if assembly_has_delegatecall(node):
                for var in _pw_addrs_read(function, ctx):
                    dests.append((node, var))
        for node in param_nodes:
            add(
                _emit(
                    "STRUCT_DELEGATECALL_SETTABLE",
                    ctx,
                    function,
                    node,
                    (
                        f"{function.name} delegatecalls a destination that is a "
                        "caller-supplied parameter of a privileged function"
                    ),
                )
            )
        for node, dest in dests:
            if dest not in ctx.privileged_writable:
                continue
            if dest.is_constant or dest.is_immutable:
                continue
            writers = ctx.privileged_writable[dest]
            writer_names = ", ".join(pw.function.name for pw in writers) or "?"
            add(
                _emit(
                    "STRUCT_DELEGATECALL_SETTABLE",
                    ctx,
                    function,
                    node,
                    f"{function.name} delegatecalls a privileged-writable destination {dest.name} (writers: {writer_names})",
                )
            )
            for pw in writers:
                add(
                    _emit(
                        "STRUCT_DELEGATECALL_SETTABLE",
                        ctx,
                        pw.function,
                        pw.node,
                        f"{pw.function.name} writes {dest.name} used as a settable delegatecall destination",
                    )
                )
    return findings


def struct_selfdestruct(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for function in unique_functions(ctx.contract):
        if is_ctor(function) or is_modifier(function):
            continue
        node = _selfdestruct_node(function)
        if node is None:
            continue
        if not _externally_reachable(ctx, function):
            continue
        if function.name in seen:
            continue
        seen.add(function.name)
        findings.append(
            _emit(
                "STRUCT_SELFDESTRUCT",
                ctx,
                function,
                node,
                f"{function.name} contains a selfdestruct reachable from a public or external function",
            )
        )
    return findings


def struct_proxy_eoa_admin(ctx: ContractContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()

    def add(item: Finding) -> None:
        key = (item.function, item.lines)
        if key in seen:
            return
        seen.add(key)
        findings.append(item)

    fallbacks = [
        fn
        for fn in unique_functions(ctx.contract)
        if _is_proxy_fallback(fn)
    ]
    fallbacks.sort(key=function_sort_key)
    for fallback in fallbacks:
        impls = _pw_addrs_read(fallback, ctx)
        for impl in impls:
            writers = ctx.privileged_writable.get(impl, [])
            if not writers:
                continue
            if not all(_single_addr_admin(pw.function) for pw in writers):
                continue
            writer_names = ", ".join(pw.function.name for pw in writers)
            add(
                _emit(
                    "STRUCT_PROXY_EOA_ADMIN",
                    ctx,
                    fallback,
                    fallback,
                    f"proxy fallback delegatecalls privileged-writable {impl.name} gated by a single state-address admin (writers: {writer_names})",
                )
            )
            for pw in writers:
                add(
                    _emit(
                        "STRUCT_PROXY_EOA_ADMIN",
                        ctx,
                        pw.function,
                        pw.node,
                        f"{pw.function.name} writes the proxy implementation {impl.name} under a single state-address admin",
                    )
                )
    return findings


RULES = [
    struct_external_gate,
    struct_delegatecall_settable,
    struct_selfdestruct,
    struct_proxy_eoa_admin,
]
