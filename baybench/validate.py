from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import Case, load_cases

SOLC_ARTIFACTS = Path.home() / ".solc-select" / "artifacts"
DEFAULT_SOLC = "0.8.20"
_IMPORT_RE = re.compile(r"""import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']""")
_OZ_PREFIX = "@openzeppelin/contracts/"


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


def oz_trees(repo_root: Path) -> list[tuple[str, Path]]:
    trees: list[tuple[str, Path]] = []
    v4 = repo_root / "vendor" / "openzeppelin-contracts"
    if v4.is_dir():
        trees.append(("v4", v4))
    v5 = repo_root / "vendor" / "openzeppelin-contracts-v5"
    if v5.is_dir():
        trees.append(("v5", v5))
    return trees


def _imported_oz_rels(source: str) -> list[str]:
    specs = set(_IMPORT_RE.findall(source))
    return [spec[len(_OZ_PREFIX) :] for spec in specs if spec.startswith(_OZ_PREFIX)]


def rank_oz_trees(source: str, trees: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    rels = _imported_oz_rels(source)
    if not rels:
        return list(trees)

    def score(item: tuple[str, Path]) -> tuple[int, int]:
        _tag, path = item
        resolved = sum(1 for rel in rels if (path / rel).is_file())
        all_resolve = 1 if resolved == len(rels) else 0
        return (-all_resolve, -resolved)

    return sorted(trees, key=score)


def _has_oz_import(source: str) -> bool:
    return any(spec.startswith("@openzeppelin/") for spec in _IMPORT_RE.findall(source))


def sol_files(case: Case) -> list[Path]:
    return sorted(p for p in case.dir.rglob("*.sol") if p.is_file())


def _solc_with_tree(bin0: Path, tree: Path | None, files: list[Path]) -> tuple[bool, str]:
    argv = [str(bin0)]
    if tree is not None:
        argv.append(f"@openzeppelin/contracts/={tree.as_posix()}/")
    argv.extend(["--bin", *map(str, files)])
    proc = subprocess.run(argv, capture_output=True, text=True)
    return proc.returncode == 0, proc.stderr or ""


def compile_case(case: Case, repo_root: Path) -> tuple[bool, str]:
    notes = (case.notes or "").lower()
    expect_fail = "expect_compile_fail" in notes or "non-compiling" in notes
    version = case.solc or DEFAULT_SOLC
    bin0 = ensure_solc(version)
    files = sol_files(case)
    source = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in files)
    has_oz = _has_oz_import(source)
    ranked = rank_oz_trees(source, oz_trees(repo_root))
    worklist: list[tuple[str | None, Path | None]] = list(ranked) if ranked else [(None, None)]

    any_ok = False
    used_tag: str | None = None
    last_stderr = ""
    for tag, tree in worklist:
        ok, stderr = _solc_with_tree(bin0, tree, files)
        last_stderr = stderr
        if ok:
            any_ok = True
            used_tag = tag
            if not expect_fail:
                break
    success = (not any_ok) if expect_fail else any_ok
    bits = [f"solc {version}", "ok" if any_ok else "fail"]
    if expect_fail:
        bits.append("expected_fail")
    if has_oz and used_tag in ("v4", "v5"):
        bits.append(f"oz={used_tag}")
    log = " ".join(bits)
    if not any_ok:
        log = f"{log} {last_stderr[:400]}"
    return success, log


def compile_fixtures(
    cases: list[Case],
    repo_root: Path | None = None,
) -> list[tuple[str, bool, str]]:
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]
    return [(case.id, *compile_case(case, repo_root)) for case in cases]
