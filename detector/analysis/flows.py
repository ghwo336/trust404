"""ETH / token outflow helpers."""

from __future__ import annotations

from typing import Any, Literal

from slither.core.declarations.function import Function
from slither.slithir.operations import (
    HighLevelCall,
    LibraryCall,
    LowLevelCall,
    Send,
    SolidityCall,
    Transfer,
)

from detector.analysis._ir import (
    SELFDESTRUCT_NAMES,
    SIG_TRANSFER,
    SIG_TRANSFER_FROM,
    assert_never,
    call_full_name,
    depends,
    fn_ir,
    is_ctor,
    is_this_expr,
    is_whole_pot_value,
    resolve_state_dest,
    solidity_call_name,
    unique_functions,
)
from detector.analysis.balances import Bindings

SendKind = Literal["transfer", "send", "call_value", "selfdestruct"]
TokenSource = Literal["param", "state", "this"]


def value_sends(
    function: Function,
) -> list[tuple[Any, Any, Any, SendKind]]:
    out: list[tuple[Any, Any, Any, SendKind]] = []
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Transfer):
                out.append((node, ir.destination, ir.call_value, "transfer"))
            elif isinstance(ir, Send):
                out.append((node, ir.destination, ir.call_value, "send"))
            elif isinstance(ir, LowLevelCall) and ir.call_value is not None:
                out.append((node, ir.destination, ir.call_value, "call_value"))
            elif isinstance(ir, SolidityCall) and solidity_call_name(ir) in SELFDESTRUCT_NAMES:
                dest = ir.arguments[0] if ir.arguments else None
                out.append((node, dest, None, "selfdestruct"))
    return out


def is_whole_pot(value_var: Any, function: Function | None = None) -> bool:
    if function is None:
        return False
    return is_whole_pot_value(value_var, function)


def payable_inflows(contract: Any) -> list[Function]:
    found: list[Function] = []
    for fn in unique_functions(contract):
        if is_ctor(fn):
            continue
        if fn.payable or fn.is_receive or fn.is_fallback:
            found.append(fn)
    return found


def token_out_calls(
    function: Function,
    bindings: Bindings,
) -> list[tuple[Any, HighLevelCall, TokenSource, Any, Any]]:
    _ = bindings
    out: list[tuple[Any, HighLevelCall, TokenSource, Any, Any]] = []
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, LibraryCall) or not isinstance(ir, HighLevelCall):
                continue
            full = call_full_name(ir)
            name = str(ir.function_name) if ir.function_name is not None else ""
            if full not in (SIG_TRANSFER, SIG_TRANSFER_FROM) and name not in (
                "transfer",
                "transferFrom",
            ):
                if full not in (SIG_TRANSFER, SIG_TRANSFER_FROM):
                    continue
            if is_this_expr(ir.destination, function):
                continue
            dest_state = resolve_state_dest(ir.destination, function)
            conv = fn_ir(function).def_of(ir.destination)
            inner = getattr(conv, "variable", None) if conv is not None else None
            source: TokenSource
            if dest_state is not None:
                source = "state"
            elif is_this_expr(ir.destination, function) or (inner is not None and is_this_expr(inner, function)):
                source = "this"
            elif any(depends(ir.destination, p, function) for p in function.parameters) or (
                inner is not None
                and any(inner is p or depends(inner, p, function) for p in function.parameters)
            ):
                source = "param"
            elif inner is not None:
                st = resolve_state_dest(inner, function)
                source = "state" if st is not None else "param"
            else:
                source = "param"
            if source not in ("param", "state", "this"):
                assert_never(source)
            args = list(ir.arguments or [])
            to_expr = args[0] if args else None
            amount_expr = args[-1] if args else None
            if full == SIG_TRANSFER_FROM or name == "transferFrom":
                to_expr = args[1] if len(args) > 1 else to_expr
                amount_expr = args[2] if len(args) > 2 else amount_expr
            out.append((node, ir, source, to_expr, amount_expr))
    return out
