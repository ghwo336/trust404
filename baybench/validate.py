from __future__ import annotations

import subprocess
from pathlib import Path

from .models import Case, load_cases

SOLC_ARTIFACTS = Path.home() / ".solc-select" / "artifacts"
DEFAULT_SOLC = "0.8.20"


def solc_binary(version: str) -> Path:
    return SOLC_ARTIFACTS / f"solc-{version}" / f"solc-{version}"


def ensure_solc(version: str) -> Path:
    path = solc_binary(version)
    if not path.is_file():
        subprocess.run(["solc-select", "install", version], check=False)
    if not path.is_file():
        raise RuntimeError(f"solc {version} not found at {path}")
    return path


def oz_remapping(repo_root: Path) -> str:
    return f"@openzeppelin/contracts/={repo_root}/vendor/openzeppelin-contracts/"


def sol_files(case: Case) -> list[Path]:
    return sorted(p for p in case.dir.rglob("*.sol") if p.is_file())


def compile_case(case: Case, repo_root: Path) -> tuple[bool, str]:
    notes = (case.notes or "").lower()
    expect_fail = "expect_compile_fail" in notes or "non-compiling" in notes
    version = case.solc or DEFAULT_SOLC
    bin0 = ensure_solc(version)
    argv = [str(bin0), oz_remapping(repo_root), "--bin", *map(str, sol_files(case))]
    proc = subprocess.run(argv, capture_output=True, text=True)
    ok = proc.returncode == 0
    success = (not ok) if expect_fail else ok
    bits = [f"solc {version}", "ok" if ok else "fail"]
    if expect_fail:
        bits.append("expected_fail")
    log = " ".join(bits)
    if not ok:
        log = f"{log} {(proc.stderr or '')[:400]}"
    return success, log


def compile_fixtures(
    cases: list[Case],
    repo_root: Path | None = None,
) -> list[tuple[str, bool, str]]:
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]
    return [(case.id, *compile_case(case, repo_root)) for case in cases]
