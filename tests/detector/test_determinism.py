"""DT-1: analysis predicates are byte-identical across PYTHONHASHSEED / processes."""

from __future__ import annotations

import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Tier 2 files whose rules-layer / Slither-overlay representatives drifted
# across PYTHONHASHSEED (DT-1). Flat copies keep bench-mode input deterministic.
_TIER2_DRIFT_FILES = (
    REPO
    / "cases/tier2_realworld/crpwarner/0x186ED770eEcEA82Def7C92DCC077C4Ba27acD5BD_sol"
    / "0x186ED770eEcEA82Def7C92DCC077C4Ba27acD5BD_sol.sol",
    REPO
    / "cases/tier2_realworld/crpwarner/0xcb6CD204D783DC8d66896A6DEf5867d332228D7b_sol"
    / "0xcb6CD204D783DC8d66896A6DEf5867d332228D7b_sol.sol",
    REPO
    / "cases/tier2_realworld/crpwarner/0x831467b7B6BF9C705dC87899d48b57eE55C8d5cc_sol"
    / "0x831467b7B6BF9C705dC87899d48b57eE55C8d5cc_sol.sol",
    REPO
    / "cases/tier2_realworld/honeybadger"
    / "uninitialised_struct_0xe6f245bb5268b16c5d79a349ec57673e477bd015_sol"
    / "uninitialised_struct_0xe6f245bb5268b16c5d79a349ec57673e477bd015_sol.sol",
    REPO
    / "cases/tier2_realworld/crpwarner/0x9dB8a10C7FE60d84397860b3aF2E686D4F90C2b7_sol"
    / "0x9dB8a10C7FE60d84397860b3aF2E686D4F90C2b7_sol.sol",
    REPO
    / "cases/tier2_realworld/pied-piper"
    / "real_0x2467aa6b5a2351416fd4c3def8462d841feeecec_sol"
    / "real_0x2467aa6b5a2351416fd4c3def8462d841feeecec_sol.sol",
)


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


def test_tier2_results_byte_identical_across_hash_seeds(tmp_path: Path) -> None:
    """DT-1: bench-mode results.json is byte-identical across PYTHONHASHSEED."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    for src in _TIER2_DRIFT_FILES:
        assert src.is_file(), src
        shutil.copy2(src, input_dir / src.name)

    seeds = ["0", "1", "2"]
    env_base = os.environ.copy()
    env_base["PYTHONPATH"] = str(REPO)
    payloads: list[bytes] = []
    for seed in seeds:
        out_path = tmp_path / f"out{seed}" / "results.json"
        out_path.parent.mkdir()
        env = env_base.copy()
        env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "detector.cli",
                str(input_dir),
                str(out_path),
            ],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        payloads.append(out_path.read_bytes())

    if not all(blob == payloads[0] for blob in payloads):
        left, right = next(
            (i, j)
            for i, a in enumerate(payloads)
            for j, b in enumerate(payloads)
            if i < j and a != b
        )
        diff = "".join(
            difflib.unified_diff(
                payloads[left].decode().splitlines(keepends=True),
                payloads[right].decode().splitlines(keepends=True),
                fromfile=f"PYTHONHASHSEED={seeds[left]}",
                tofile=f"PYTHONHASHSEED={seeds[right]}",
                n=3,
            )
        )
        raise AssertionError(
            f"results.json differed across PYTHONHASHSEED values:\n{diff}"
        )

    data = json.loads(payloads[0])
    verdicts = {item["file"]: item["verdict"] for item in data["results"]}
    assert verdicts, "expected six file results"
    assert all(verdict == "Malicious" for verdict in verdicts.values()), verdicts
    assert len(verdicts) == len(_TIER2_DRIFT_FILES), verdicts


if __name__ == "__main__":
    print(snapshot())
