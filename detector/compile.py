"""Solc selection, OpenZeppelin remapping, and Slither construction."""

from __future__ import annotations

import os
import re
from pathlib import Path

from slither import Slither

INSTALLED_SOLC = ("0.4.26", "0.5.17", "0.6.12", "0.7.6", "0.8.20", "0.8.24")
DEFAULT_SOLC = "0.8.20"
SOLC_ARTIFACTS = Path.home() / ".solc-select" / "artifacts"

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


class CompileError(Exception):
    """Raised when solc is missing or Slither / crytic-compile fails."""


def _ver_tuple(version: str) -> tuple[int, int, int]:
    parts = [int(piece) for piece in version.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def pick_solc(source: str) -> str:
    """Pick an installed solc by nearest same-minor version; default 0.8.20."""
    match = _PRAGMA_RE.search(source)
    if not match:
        return DEFAULT_SOLC
    found = _VERSION_RE.findall(match.group(1))
    if not found:
        return DEFAULT_SOLC
    requested = _ver_tuple(found[0])
    same_minor = [ver for ver in INSTALLED_SOLC if _ver_tuple(ver)[:2] == requested[:2]]
    if not same_minor:
        return DEFAULT_SOLC

    def rank(ver: str) -> tuple[int, int, tuple[int, int, int]]:
        actual = _ver_tuple(ver)
        distance = abs(actual[2] - requested[2])
        prefer_ge = 0 if actual >= requested else 1
        return distance, prefer_ge, actual

    return min(same_minor, key=rank)


def solc_binary(version: str) -> Path:
    return SOLC_ARTIFACTS / f"solc-{version}" / f"solc-{version}"


def _oz_dir() -> Path | None:
    env = os.environ.get("DETECTOR_OZ_DIR")
    candidates = []
    if env:
        candidates.append(Path(env))
    repo = Path(__file__).resolve().parents[1]
    candidates.append(repo / "vendor" / "openzeppelin-contracts")
    candidates.append(Path("/app/vendor/openzeppelin-contracts"))
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def oz_remapping() -> str | None:
    vendor = _oz_dir()
    if vendor is None:
        return None
    return f"@openzeppelin/contracts/={vendor.as_posix()}/"


def compile_file(path: Path) -> Slither:
    path = Path(path).resolve()
    source = path.read_text(encoding="utf-8", errors="replace")
    version = pick_solc(source)
    solc_bin = solc_binary(version)
    if not solc_bin.is_file():
        raise CompileError(f"solc {version}: binary not found at {solc_bin}")
    remap = oz_remapping()
    oz = _oz_dir()
    allow_parts = [str(path.parent)]
    if oz is not None:
        allow_parts.append(str(oz.resolve()))
    solc_args = f"--allow-paths {','.join(allow_parts)}"
    try:
        return Slither(
            str(path),
            solc=str(solc_bin),
            solc_remaps=[remap] if remap else [],
            solc_args=solc_args,
        )
    except Exception as exc:
        raise CompileError(f"solc {version}: {str(exc)[:500]}") from exc
