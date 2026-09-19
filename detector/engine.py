"""Per-file worker (spawn + timeout), batch loop, and target-contract selection."""

from __future__ import annotations

import logging
import multiprocessing
from pathlib import Path

from slither import Slither

from detector.analysis.context import ContractContext
from detector.compile import CompileError, compile_file
from detector.model import FileResult, Finding
from detector.policy import decide
from detector.rules import RULES

logger = logging.getLogger("detector.engine")

WORKER_TIMEOUT_DEFAULT = 120


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


def _analyze_in_process(path: str, rel: str) -> dict:
    slither = compile_file(Path(path))
    findings: list[Finding] = []
    input_root = _input_root(Path(path), rel)
    for contract in target_contracts(slither, Path(path)):
        ctx = ContractContext(slither=slither, contract=contract, input_root=input_root)
        for rule in RULES:
            findings.extend(rule(ctx))
    verdict, reason = decide(findings)
    return FileResult(
        file=rel,
        verdict=verdict,
        reason=reason,
        findings=tuple(findings),
    ).to_json()


def _worker(fn, path: str, rel: str, queue) -> None:
    try:
        queue.put(("ok", fn(path, rel)))
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
) -> FileResult:
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(_analyze_in_process, str(path), rel, queue))
    proc.start()
    proc.join(timeout_s)
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        if proc.is_alive():
            proc.kill()
            proc.join()
        return FileResult(rel, "Uncertain", reason="timeout")
    try:
        status, payload = queue.get(timeout=1)
    except Exception as exc:
        logger.warning("worker exited without result for %s: %s", rel, exc)
        return FileResult(rel, "Uncertain", reason="analysis_error")
    if status == "ok":
        try:
            return _file_result_from_worker(payload)
        except Exception as exc:
            logger.warning("worker returned invalid payload for %s: %s", rel, exc)
            return FileResult(rel, "Uncertain", reason="analysis_error")
    if status == "compile_failed":
        return FileResult(rel, "Uncertain", reason="compile_failed")
    return FileResult(rel, "Uncertain", reason="analysis_error")


def analyze_dir(input_dir: Path, *, timeout_s: int = WORKER_TIMEOUT_DEFAULT) -> list[FileResult]:
    root = Path(input_dir).resolve()
    results: list[FileResult] = []
    for path in sorted(p for p in root.rglob("*.sol") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        try:
            results.append(analyze_file(path, rel, timeout_s=timeout_s))
        except Exception as exc:
            logger.warning("analyze_dir failed for %s: %s", rel, exc)
            results.append(FileResult(rel, "Uncertain", reason="analysis_error"))
    return results
