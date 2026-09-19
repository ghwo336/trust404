"""Per-contract analysis context shared by rules."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

from detector.analysis import balances, privilege, transfer_path
from detector.analysis._ir import (
    CACHE_AUTH,
    CACHE_BRANCH,
    CACHE_FNIR,
    contract_cache,
    is_under_root,
    pin_contract_caches,
    unique_functions,
)


@dataclass
class ContractContext:
    slither: Any
    contract: Any
    input_root: Path
    # When the retry ladder compiled a scratch-mirror rewrite, Slither filenames point at the
    # mirror. Treat that tree as in-project too (same relative layout as `input_root`).
    compile_root: Path | None = None

    def __post_init__(self) -> None:
        # Pin strong-ref caches on the live contract (reachable from slither).
        pin_contract_caches(self.contract)
        self._fnir_cache = contract_cache(self.contract, CACHE_FNIR)
        self._auth_atoms_cache = contract_cache(self.contract, CACHE_AUTH)
        self._branch_atoms_cache = contract_cache(self.contract, CACHE_BRANCH)

    def is_from_input_root(self, function_or_contract: Any) -> bool:
        if is_under_root(function_or_contract, self.input_root):
            return True
        extra = self.compile_root
        if extra is None:
            return False
        extra_res = Path(extra).resolve()
        if extra_res == Path(self.input_root).resolve():
            return False
        return is_under_root(function_or_contract, extra_res)

    @cached_property
    def functions(self) -> list[Any]:
        return unique_functions(self.contract)

    @cached_property
    def bindings(self):
        return balances.bind(self.contract)

    @cached_property
    def privileged_writes(self):
        return privilege.privileged_writes(self.contract)

    @cached_property
    def privileged_writable(self):
        return privilege.privileged_writable(self.contract)

    @cached_property
    def auth_vars(self):
        return privilege.auth_vars(self.contract)

    @cached_property
    def transfer_roots(self):
        return transfer_path.transfer_roots(self.contract, self)

    @cached_property
    def transfer_path(self):
        return transfer_path.transfer_path(self.contract, self)

    @cached_property
    def end_nodes(self):
        return transfer_path.end_nodes(self.contract, self)

    @cached_property
    def gate_reads(self):
        return transfer_path.gate_reads(self)

    @cached_property
    def external_calls_on_path(self):
        return transfer_path.external_calls_on_path(self)
