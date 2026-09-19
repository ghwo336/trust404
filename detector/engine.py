"""Per-file worker (spawn + timeout), batch loop, and target-contract selection."""

from __future__ import annotations

import logging
import multiprocessing
from pathlib import Path

from slither import Slither

from detector.analysis.context import ContractContext
from detector.compile import (
    CompileError,
    cleanup_temp_copies,
    compile_file_ex,
    is_temp_copy,
    scratch_session,
)
from detector.model import FileResult, Finding
from detector.policy import decide, finalize
from detector.rules import RULES

logger = logging.getLogger("detector.engine")

WORKER_TIMEOUT_DEFAULT = 120


def _compile_root(compiled, input_root: Path) -> Path | None:
    """Mirror root Slither compiled, or None when it parsed the original file."""
    source = Path(compiled.source_path).resolve()
    canonical = Path(compiled.canonical_path).resolve()
    if source == canonical:
        return None
    try:
        rel = canonical.relative_to(Path(input_root).resolve())
    except ValueError:
        return source.parent
    cursor = Path(compiled.source_path)
    for _ in rel.parts:
        cursor = cursor.parent
    return cursor


def _input_root(path: Path, rel: str) -> Path:
    resolved = Path(path).resolve()
    rel_norm = rel.replace("\\", "/").lstrip("/")
    posix = resolved.as_posix()
    if rel_norm and posix.endswith(rel_norm):
        root = posix[: -len(rel_norm)].rstrip("/")
        return Path(root) if root else resolved.parent
    return resolved.parent


def target_contracts(slither: Slither, path: Path) -> list:
    resolved = Path(path).resolve()
    selected = []
    for contract in slither.contracts:
        mapping = contract.source_mapping
        if mapping is None or not mapping.filename.absolute:
            continue
        declared_in = Path(mapping.filename.absolute).resolve()
        if declared_in != resolved:
            continue
        if contract.is_interface or contract.is_library or contract.is_abstract:
            continue
        selected.append(contract)
    selected.sort(key=lambda contract: (contract.source_mapping.start, contract.name))
    inherited_ids = {id(base) for contract in selected for base in contract.inheritance}
    leaves = [contract for contract in selected if id(contract) not in inherited_ids]
    return [contract for contract in leaves if _has_implemented_body(contract)]


def _has_implemented_body(contract) -> bool:
    """Drop 0.4 callback stubs (e.g. ApproveAndCallFallBack) that Slither does not mark abstract."""
    declared = [
        fn
        for fn in getattr(contract, "functions_declared", []) or []
        if not fn.is_constructor and not fn.is_constructor_variables
    ]
    if not declared:
        return True
    if all((not fn.is_implemented) or getattr(fn, "is_empty", False) for fn in declared):
        return False
    return True


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.function, finding.lines, finding.severity)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _lib_pkg_is_dependency(pkg_dir: Path) -> bool:
    if (pkg_dir / "package.json").exists() or (pkg_dir / "foundry.toml").exists():
        return True
    if (pkg_dir / ".git").exists():
        return True
    return (pkg_dir / "src").is_dir() or (pkg_dir / "contracts").is_dir()


def is_dependency_target(path: Path, root: Path) -> bool:
    """True for node_modules trees and package-shaped lib/<pkg>/ (do not resolve symlinks)."""
    try:
        parts = Path(path).relative_to(root).parts
    except ValueError:
        return False
    if "node_modules" in parts:
        return True
    for i, part in enumerate(parts[:-1]):
        if part != "lib":
            continue
        nxt = parts[i + 1]
        if nxt.endswith(".sol") and i + 2 == len(parts):
            continue
        if _lib_pkg_is_dependency(root.joinpath(*parts[: i + 2])):
            return True
    return False


def _iter_sol_files(root: Path) -> list[Path]:
    """Sorted `.sol` files under root; follows directory symlinks and rejects cycles."""
    found: list[Path] = []
    seen: set[str] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            resolved = str(current.resolve())
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        for child in children:
            if child.is_dir():
                stack.append(child)
            elif child.is_file() and child.suffix == ".sol" and not is_temp_copy(child):
                found.append(child)
    found.sort(key=lambda item: item.as_posix())
    return found


def _analyze_in_process(path: str, rel: str, input_root: str | None = None) -> dict:
    """Compile (with the retry ladder), run rules per target contract, decide.

    Returns FileResult JSON plus an internal `compile_note` key (relayed to the parent's log;
    never written to results.json).
    """
    file_path = Path(path)
    root = Path(input_root).resolve() if input_root else _input_root(file_path, rel)
    compiled = compile_file_ex(file_path, input_root=root)
    if compiled.note:
        logger.info("compile note for %s: %s", rel, compiled.note)
    slither = compiled.slither
    findings: list[Finding] = []
    # Provenance root is the CLI input directory (original path). When the ladder rewrote
    # into a scratch mirror, Slither filenames point there — pass that tree as compile_root.
    compile_root = _compile_root(compiled, root)
    for contract in target_contracts(slither, compiled.source_path):
        ctx = ContractContext(
            slither=slither,
            contract=contract,
            input_root=root,
            compile_root=compile_root,
        )
        raw: list[Finding] = []
        for rule in RULES:
            raw.extend(rule(ctx))
        findings.extend(finalize(raw))
    findings = _dedupe_findings(findings)
    verdict, reason = decide(findings)
    payload = FileResult(
        file=rel,
        verdict=verdict,
        reason=reason,
        findings=tuple(findings),
    ).to_json(internal=True)
    if compiled.note:
        payload["compile_note"] = compiled.note
    return payload


def _worker(fn, path: str, rel: str, queue, input_root: str | None = None) -> None:
    try:
        queue.put(("ok", fn(path, rel, input_root)))
    except CompileError as exc:
        logger.warning("compile failed for %s: %s", rel, exc)
        queue.put(("compile_failed", None))
    except Exception as exc:
        logger.warning("analysis error for %s: %s", rel, exc)
        queue.put(("analysis_error", None))


def _file_result_from_worker(obj: dict) -> FileResult:
    findings = tuple(
        Finding(
            rule_id=item["rule_id"],
            family=item["family"],
            severity=item["severity"],
            contract=item.get("contract") or "",
            function=item.get("function") or "",
            lines=tuple(item.get("lines") or ()),
            reasoning=item.get("reasoning") or "",
            base_severity=item.get("base_severity") or item["severity"],
            discriminators=tuple(item.get("discriminators") or ()),
        )
        for item in (obj.get("findings") or ())
    )
    return FileResult(
        file=obj["file"],
        verdict=obj["verdict"],
        reason=obj.get("reason") or "",
        findings=findings,
    )


def analyze_file(
    path: Path,
    rel: str,
    *,
    timeout_s: int = WORKER_TIMEOUT_DEFAULT,
    input_root: Path | None = None,
) -> FileResult:
    root = Path(input_root).resolve() if input_root is not None else _input_root(path, rel)
    with scratch_session():
        return _run_file_worker(path, rel, timeout_s=timeout_s, root=root)


def _run_file_worker(path: Path, rel: str, *, timeout_s: int, root: Path) -> FileResult:
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    proc = ctx.Process(
        target=_worker,
        args=(_analyze_in_process, str(path), rel, queue, str(root)),
    )
    proc.start()
    proc.join(timeout_s)
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        if proc.is_alive():
            proc.kill()
            proc.join()
        # A killed worker skips compile_file_ex's cleanup; drop any scratch mirror it left behind.
        for leftover in cleanup_temp_copies(path):
            logger.warning("removed leftover ladder scratch %s after timeout", leftover)
        return FileResult(rel, "Uncertain", reason="timeout")
    try:
        status, payload = queue.get(timeout=1)
    except Exception as exc:
        logger.warning("worker exited without result for %s: %s", rel, exc)
        cleanup_temp_copies(path)
        return FileResult(rel, "Uncertain", reason="analysis_error")
    if status == "ok":
        note = payload.get("compile_note") if isinstance(payload, dict) else None
        if note:
            logger.info("compile note for %s: %s", rel, note)
        try:
            return _file_result_from_worker(payload)
        except Exception as exc:
            logger.warning("worker returned invalid payload for %s: %s", rel, exc)
            return FileResult(rel, "Uncertain", reason="analysis_error")
    if status == "compile_failed":
        return FileResult(rel, "Uncertain", reason="compile_failed")
    return FileResult(rel, "Uncertain", reason="analysis_error")


def analyze_dir(
    input_dir: Path, *, timeout_s: int = WORKER_TIMEOUT_DEFAULT
) -> tuple[list[FileResult], int]:
    root = Path(input_dir).resolve()
    results: list[FileResult] = []
    skipped = 0
    with scratch_session():
        # Follow dir symlinks (Foundry/Hardhat vendored trees) but skip leftover __relaxed__ names.
        for path in _iter_sol_files(root):
            if is_dependency_target(path, root):
                skipped += 1
                continue
            rel = path.relative_to(root).as_posix()
            try:
                results.append(analyze_file(path, rel, timeout_s=timeout_s, input_root=root))
            except Exception as exc:
                logger.warning("analyze_dir failed for %s: %s", rel, exc)
                results.append(FileResult(rel, "Uncertain", reason="analysis_error"))
        if skipped:
            logger.info(
                "skipped %s dependency file(s) under node_modules/ or lib/<pkg>/ "
                "(analysed as imports only)",
                skipped,
            )
        return results, skipped
