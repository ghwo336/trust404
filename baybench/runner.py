from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from .models import Case, SchemaError, ToolResult, load_cases, parse_result

REPO_ROOT = Path(__file__).resolve().parents[1]


class RunnerError(RuntimeError):
    pass


_UNSET_ENV_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def stage_tiers(
    cases_root: str | Path,
    tiers: list[str] | None,
    dest: str | Path,
) -> dict[str, Case]:
    cases_root = Path(cases_root)
    dest = Path(dest)
    cases = load_cases(cases_root, tiers)
    staged: dict[str, Case] = {}
    for case in cases:
        case_dest = dest / case.id
        for src in case.dir.rglob("*"):
            if not src.is_file() or src.name == "labels.yaml":
                continue
            rel = src.relative_to(case.dir)
            dst = case_dest / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        expected = case_dest / case.file
        if not expected.is_file():
            raise RunnerError(f"staged file missing: {expected}")
        staged[case.staged_file] = case
    return staged


def docker_run_argv(image: str, input_dir: Path, out_dir: Path) -> list[str]:
    input_dir = Path(input_dir).resolve()
    out_dir = Path(out_dir).resolve()
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{input_dir}:/input:ro",
        "-v",
        f"{out_dir}:/output",
        image,
    ]


def run_tool(
    tool_cfg: dict,
    input_dir: str | Path,
    out_dir: str | Path,
    use_docker: bool = True,
    timeout: int = 600,
    cwd: str | Path | None = None,
) -> dict:
    input_dir = Path(input_dir).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if use_docker:
        image = tool_cfg.get("image")
        if not image:
            raise RunnerError(f"tool {tool_cfg.get('name')!r} missing 'image' for docker mode")
        argv = docker_run_argv(image, input_dir, out_dir)
        run_cwd = None
    else:
        cmd = tool_cfg.get("cmd")
        if not cmd:
            raise RunnerError(f"tool {tool_cfg.get('name')!r} missing 'cmd' for command mode")
        substituted = cmd.replace("{input}", str(input_dir)).replace("{output}", str(out_dir))
        expanded = os.path.expandvars(substituted)
        leftover = sorted(set(_UNSET_ENV_RE.findall(expanded)))
        if leftover:
            name = tool_cfg.get("name")
            raise RunnerError(
                f"tool {name!r}: cmd references unset environment variable(s) {leftover}; "
                f"export them (e.g. `export T404_DIR=~/T404`) or edit baybench/tools.yaml"
            )
        argv = shlex.split(expanded)
        run_cwd = str(cwd) if cwd is not None else str(REPO_ROOT)
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=run_cwd,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(f"timeout after {timeout}s running {argv!r}") from exc
    elapsed = time.perf_counter() - t0
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    results_path = out_dir / "results.json"
    if not results_path.is_file():
        raise RunnerError(
            f"missing results.json at {results_path}: {stderr[-500:]}"
        )
    result: ToolResult = parse_result(results_path)
    return {
        "tool": tool_cfg["name"],
        "result": result,
        "wall_s": round(elapsed, 4),
        "returncode": int(proc.returncode),
        "stdout": stdout,
        "stderr": stderr,
        "results_path": str(results_path),
        "argv": argv,
    }


def run(
    tool_cfg: dict,
    cases_root: str | Path,
    tiers: list[str] | None = None,
    use_docker: bool = True,
    work_dir: str | Path | None = None,
    timeout: int = 600,
) -> dict:
    if work_dir is None:
        work_dir = REPO_ROOT / ".bench_work" / tool_cfg["name"]
    work_dir = Path(work_dir)
    input_dir = work_dir / "input"
    out_dir = work_dir / "output"
    if input_dir.exists():
        shutil.rmtree(input_dir)
    input_dir.mkdir(parents=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    staged = stage_tiers(cases_root, tiers, input_dir)
    res = run_tool(tool_cfg, input_dir, out_dir, use_docker, timeout)
    res["staged"] = staged
    res["timings"] = [res["wall_s"]]
    return res
