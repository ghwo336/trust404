"""DT-1: analysis predicates are byte-identical across PYTHONHASHSEED / processes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _fn_sig(fn) -> str:
    return fn.solidity_signature or fn.full_name or fn.name


def snapshot() -> str:
    import logging

    logging.disable(logging.WARNING)

    from detector.analysis.balances import balance_writes
    from detector.analysis.context import ContractContext
    from detector.analysis.transfer_path import _path_meta
    from detector.compile import compile_file
    from detector.engine import target_contracts
    from tests.detector.conftest import TIER3, tier1_sol

    payloads: dict[str, object] = {}
    cases = [
        ("hidden_mint", tier1_sol("BAL_TRANSFER_HIDDEN_MINT", "mal"), None),
        ("exit_gate", tier1_sol("EXIT_ADDR_GATE", "mal"), None),
        ("usdc", TIER3 / "usdc_fiattoken" / "FiatTokenV1.sol", "FiatTokenV1"),
    ]
    for label, path, name in cases:
        slither = compile_file(path)
        contracts = target_contracts(slither, path)
        if name is not None:
            contract = next(c for c in contracts if c.name == name)
        else:
            contract = contracts[0]
        ctx = ContractContext(slither=slither, contract=contract, input_root=path.parent)
        meta = _path_meta(ctx)
        path_fns = sorted(ctx.transfer_path, key=lambda f: (_fn_sig(f), f.name or ""))
        writes_by_fn = {}
        for fn in path_fns:
            roles = meta.roles.get(id(fn), {})
            writes = balance_writes(fn, ctx.bindings, param_roles=roles or None)
            writes_by_fn[_fn_sig(fn)] = sorted(
                (w.kind, w.key_source, w.value_is_raw_amount) for w in writes
            )
        body = {
            "privileged_writers": sorted(
                (pw.var.name, _fn_sig(pw.function), pw.mode, pw.node.node_id)
                for pw in ctx.privileged_writes
            ),
            "privileged_writable": sorted(v.name for v in ctx.privileged_writable),
            "gate_reads": sorted(
                (g.var.name, g.shape, g.key_source) for g in ctx.gate_reads
            ),
            "balance_writes": writes_by_fn,
            "bindings": {
                "balance": [v.name for v in ctx.bindings.balance_vars],
                "supply": [v.name for v in ctx.bindings.supply_vars],
                "allowance": [v.name for v in ctx.bindings.allowance_vars],
            },
        }
        if label == "hidden_mint":
            inner = next(f for f in ctx.contract.functions if f.name == "_transfer")
            roles = {
                inner.parameters[0]: "from",
                inner.parameters[1]: "to",
                inner.parameters[2]: "amount",
            }
            ws = balance_writes(inner, ctx.bindings, param_roles=roles)
            body["probe"] = sorted(
                (w.kind, w.key_source, w.value_is_raw_amount) for w in ws
            )
        payloads[label] = body
    return json.dumps(payloads, sort_keys=True, separators=(",", ":"))


def test_analysis_byte_identical_across_hash_seeds() -> None:
    seeds = ["0", "1", "2", "3", "random"]
    outputs: list[str] = []
    env_base = os.environ.copy()
    env_base["PYTHONPATH"] = str(REPO)
    for seed in seeds:
        env = env_base.copy()
        env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "from tests.detector.test_determinism import snapshot; print(snapshot())",
            ],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        outputs.append(proc.stdout)
    assert all(out == outputs[0] for out in outputs), (
        "analysis snapshot differed across PYTHONHASHSEED values:\n"
        + "\n".join(f"seed={s} n={len(o)}" for s, o in zip(seeds, outputs))
    )
    data = json.loads(outputs[0])
    assert data["hidden_mint"]["probe"] == [
        ["credit", "state", True],
        ["credit", "to", True],
        ["debit", "from", True],
    ]


if __name__ == "__main__":
    print(snapshot())
