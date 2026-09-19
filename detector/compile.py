"""Solc selection, OpenZeppelin remapping, Slither construction, and the compile retry ladder."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from slither import Slither

INSTALLED_SOLC = (
    "0.4.26",
    "0.5.17",
    "0.6.12",
    "0.7.6",
    "0.8.20",
    # Contiguous 0.8.24..0.8.37 so an exact `pragma solidity 0.8.3x;` in a recent sample
    # resolves to a real binary instead of a nearest-minor mismatch (compile_failed).
    "0.8.24",
    "0.8.25",
    "0.8.26",
    "0.8.27",
    "0.8.28",
    "0.8.29",
    "0.8.30",
    "0.8.31",
    "0.8.32",
    "0.8.33",
    "0.8.34",
    "0.8.35",
    "0.8.36",
    "0.8.37",
)
DEFAULT_SOLC = "0.8.20"
SOLC_ARTIFACTS = Path.home() / ".solc-select" / "artifacts"

# Retry ladder knobs (see docs/specs/detector.md, "Retry ladder").
MAX_SOLC_ATTEMPTS = 5
NO_PRAGMA_LADDER = ("0.4.26", "0.5.17", "0.6.12", "0.7.6")
RELAXED_PRAGMA = "pragma solidity >=0.4.0;"
TEMP_COPY_SUFFIX = ".__relaxed__.sol"

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_CONSTRAINT_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_SPDX_LINE_RE = re.compile(r"^[ \t]*//[ \t]*SPDX-License-Identifier:[^\n]*$", re.MULTILINE)
_SPDX_BLOCK_RE = re.compile(r"/\*[ \t]*SPDX-License-Identifier:[^*\n]*\*/")

_RELAX_MARKER = "requires different compiler version"
_SPDX_MARKER = "Multiple SPDX license identifiers"
_FIX_RELAX = "relax"
_FIX_SPDX = "spdx"

Version = tuple[int, int, int]
Constraint = tuple[str, Version]  # op in {">=", ">", "<=", "<", "="}


class CompileError(Exception):
    """Raised when solc is missing or Slither / crytic-compile fails."""


@dataclass(frozen=True)
class CompileResult:
    """A successful compile.

    `source_path` is the file Slither actually parsed: identical to `canonical_path` unless the
    retry ladder had to write a same-directory temp copy (already deleted by the time this is
    returned; Slither caches source text at construction). Filenames inside `slither` point at
    `source_path`, so callers that filter contracts by file (engine.target_contracts) must pass
    `source_path`, not `canonical_path`. `note` is None when the first attempt succeeded.
    """

    slither: Slither
    version: str
    note: str | None
    source_path: Path
    canonical_path: Path


def _ver_tuple(version: str) -> Version:
    parts = [int(piece) for piece in version.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


# --- pragma parsing ---------------------------------------------------------------------------


def _pragma_exprs(source: str) -> list[str]:
    """Every `pragma solidity <expr>;` expression in the file, in order, whitespace-normalised."""
    return [" ".join(match.group(1).split()) for match in _PRAGMA_RE.finditer(source)]


def _caret_upper(major: int, minor: int | None, patch: int | None) -> Version:
    """`^` allows changes that do not modify the left-most non-zero component."""
    if major > 0:
        return major + 1, 0, 0
    if minor is None:
        return 1, 0, 0
    if minor > 0:
        return 0, minor + 1, 0
    if patch is None:
        return 0, 1, 0
    return 0, 0, patch + 1


def _token_constraints(op: str, major: int, minor: int | None, patch: int | None) -> list[Constraint]:
    lower: Version = (major, minor or 0, patch or 0)
    # Upper bound implied by a partial literal (X-range): `0.8` == >=0.8.0 <0.9.0, `0` == <1.0.0.
    if minor is None:
        partial_upper: Version | None = (major + 1, 0, 0)
    elif patch is None:
        partial_upper = (major, minor + 1, 0)
    else:
        partial_upper = None
    if op == "^":
        return [(">=", lower), ("<", _caret_upper(major, minor, patch))]
    if op == "~":
        upper = (major + 1, 0, 0) if minor is None else (major, minor + 1, 0)
        return [(">=", lower), ("<", upper)]
    if op == ">=":
        return [(">=", lower)]
    if op == "<":
        return [("<", lower)]
    if op == ">":
        return [(">", lower)] if partial_upper is None else [(">=", partial_upper)]
    if op == "<=":
        return [("<=", lower)] if partial_upper is None else [("<", partial_upper)]
    # "=" or bare literal
    if partial_upper is None:
        return [("=", lower)]
    return [(">=", lower), ("<", partial_upper)]


def _parse_groups(expr: str) -> list[list[Constraint]]:
    """`a b || c` -> [[a, b], [c]]; a version satisfies the expression if it satisfies any group."""
    groups: list[list[Constraint]] = []
    for alternative in expr.split("||"):
        constraints: list[Constraint] = []
        for match in _CONSTRAINT_RE.finditer(alternative):
            op = match.group(1) or "="
            major = int(match.group(2))
            minor = int(match.group(3)) if match.group(3) is not None else None
            patch = int(match.group(4)) if match.group(4) is not None else None
            constraints.extend(_token_constraints(op, major, minor, patch))
        if constraints:
            groups.append(constraints)
    return groups


def _holds(version: Version, constraint: Constraint) -> bool:
    op, bound = constraint
    if op == ">=":
        return version >= bound
    if op == ">":
        return version > bound
    if op == "<=":
        return version <= bound
    if op == "<":
        return version < bound
    return version == bound


def _satisfies(version: str, statements: list[list[list[Constraint]]]) -> bool:
    actual = _ver_tuple(version)
    return all(
        any(all(_holds(actual, c) for c in group) for group in groups)
        for groups in statements
    )


def _nearest_same_minor(requested: Version) -> str:
    same_minor = [ver for ver in INSTALLED_SOLC if _ver_tuple(ver)[:2] == requested[:2]]
    if not same_minor:
        return DEFAULT_SOLC

    def rank(ver: str) -> tuple[int, int, Version]:
        actual = _ver_tuple(ver)
        distance = abs(actual[2] - requested[2])
        prefer_ge = 0 if actual >= requested else 1
        return distance, prefer_ge, actual

    return min(same_minor, key=rank)


def pick_solc(source: str) -> str:
    """Pick an installed solc for `source`.

    Rule: parse every `pragma solidity` statement (all must hold; `||` alternatives inside one
    statement are OR-ed). Prefer DEFAULT_SOLC whenever it satisfies; otherwise the LOWEST
    satisfying installed version (old code written for 0.4 usually breaks under 0.5 semantics,
    and the oldest satisfying patch is closest to what the author tested); otherwise the legacy
    nearest-same-minor of the first version literal (default 0.8.20 for an unknown minor). The
    legacy fallback is what makes an exact `0.4.24` pick 0.4.26 — solc then rejects the pragma
    and the retry ladder relaxes it.
    """
    exprs = _pragma_exprs(source)
    if not exprs:
        return DEFAULT_SOLC
    statements = [groups for groups in (_parse_groups(expr) for expr in exprs) if groups]
    if statements:
        satisfying = [ver for ver in INSTALLED_SOLC if _satisfies(ver, statements)]
        if DEFAULT_SOLC in satisfying:
            return DEFAULT_SOLC
        if satisfying:
            return min(satisfying, key=_ver_tuple)
    found = _VERSION_RE.findall(exprs[0])
    if not found:
        return DEFAULT_SOLC
    return _nearest_same_minor(_ver_tuple(found[0]))


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


# --- retry ladder -----------------------------------------------------------------------------


def is_temp_copy(path: Path) -> bool:
    """True for the same-directory temp copies written by the retry ladder (`<stem>.__relaxed__.sol`)."""
    return Path(path).name.endswith(TEMP_COPY_SUFFIX)


def _temp_copy_path(canonical: Path) -> Path:
    return canonical.with_name(canonical.stem + TEMP_COPY_SUFFIX)


def cleanup_temp_copies(path: Path) -> list[Path]:
    """Remove the ladder temp copy for `path` if a killed worker left one behind; returns what was removed."""
    temp = _temp_copy_path(Path(path).resolve())
    if not temp.is_file():
        return []
    temp.unlink(missing_ok=True)
    return [temp]


def _relax_pragmas(source: str) -> str:
    """Replace every `pragma solidity ...;` with RELAXED_PRAGMA, preserving line count."""

    def replace(match: re.Match[str]) -> str:
        return RELAXED_PRAGMA + "\n" * match.group(0).count("\n")

    return _PRAGMA_RE.sub(replace, source)


def _strip_duplicate_spdx(source: str) -> str:
    """Blank every SPDX comment after the first, preserving line count."""
    seen = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal seen
        seen += 1
        if seen == 1:
            return match.group(0)
        return "\n" * match.group(0).count("\n")

    out = _SPDX_LINE_RE.sub(replace, source)
    return _SPDX_BLOCK_RE.sub(replace, out)


def _apply_fixes(source: str, fixes: set[str]) -> str:
    if _FIX_RELAX in fixes:
        source = _relax_pragmas(source)
    if _FIX_SPDX in fixes:
        source = _strip_duplicate_spdx(source)
    return source


def _fixes_for(error: str, *, has_pragma: bool) -> set[str]:
    fixes: set[str] = set()
    if has_pragma and _RELAX_MARKER in error:
        fixes.add(_FIX_RELAX)
    if _SPDX_MARKER in error:
        fixes.add(_FIX_SPDX)
    return fixes


def _first_error_line(error: str) -> str:
    """First solc diagnostic (from its `Error` token on) for the attempt log; else the first line."""
    for line in error.splitlines():
        idx = line.find("Error")
        if idx >= 0:
            return line[idx:].strip()[:200]
    for line in error.splitlines():
        if line.strip():
            return line.strip()[:200]
    return error[:200]


def _note(fixes: set[str], pragmas: list[str], version: str) -> str:
    parts: list[str] = []
    if _FIX_RELAX in fixes:
        distinct = list(dict.fromkeys(pragmas))
        parts.append(f"pragma {' & '.join(distinct)} relaxed")
    if _FIX_SPDX in fixes:
        parts.append("duplicate SPDX identifiers removed")
    if not pragmas:
        parts.append("no pragma")
    parts.append(f"compiled with {version}")
    return "; ".join(parts)


def _build_slither(target: Path, version: str, allow_root: Path) -> Slither:
    solc_bin = solc_binary(version)
    if not solc_bin.is_file():
        raise CompileError(f"solc {version}: binary not found at {solc_bin}")
    remap = oz_remapping()
    oz = _oz_dir()
    allow_parts = [str(allow_root)]
    if oz is not None:
        allow_parts.append(str(oz.resolve()))
    return Slither(
        str(target),
        solc=str(solc_bin),
        solc_remaps=[remap] if remap else [],
        solc_args=f"--allow-paths {','.join(allow_parts)}",
    )


class _Ladder:
    """Bounded sequence of Slither constructions for one file; records an attempt log."""

    def __init__(self, canonical: Path) -> None:
        self.canonical = canonical
        self.log: list[str] = []

    @property
    def exhausted(self) -> bool:
        return len(self.log) >= MAX_SOLC_ATTEMPTS

    def attempt(self, target: Path, version: str) -> Slither | str:
        """Return a Slither on success, else the error text."""
        try:
            slither = _build_slither(target, version, self.canonical.parent)
        except CompileError as exc:  # missing binary: recorded, does not spawn solc
            self.log.append(f"{version} on {target.name}: {exc}")
            return str(exc)
        except Exception as exc:
            error = str(exc)
            self.log.append(f"{version} on {target.name}: {_first_error_line(error)}")
            return error
        self.log.append(f"{version} on {target.name}: ok")
        return slither


def compile_file_ex(path: Path) -> CompileResult:
    """Compile `path` with pick_solc's version, then climb the retry ladder on failure.

    Ladder (each rung is a fresh Slither construction; at most MAX_SOLC_ATTEMPTS in total):
      a. error says "requires different compiler version" -> same-directory temp copy with every
         `pragma solidity` statement replaced by RELAXED_PRAGMA, same version;
      b. no pragma and the default fails -> NO_PRAGMA_LADDER versions in order;
      c. error says "Multiple SPDX license identifiers" -> temp copy with all but the first SPDX
         comment blanked (combined with a. when both apply);
      d. anything else -> CompileError carrying the ORIGINAL first error plus the attempt log.
    Temp copies preserve line numbers and are deleted before returning or raising.
    """
    canonical = Path(path).resolve()
    source = canonical.read_text(encoding="utf-8", errors="replace")
    pragmas = _pragma_exprs(source)
    version = pick_solc(source)
    if not solc_binary(version).is_file():
        raise CompileError(f"solc {version}: binary not found at {solc_binary(version)}")

    ladder = _Ladder(canonical)
    outcome = ladder.attempt(canonical, version)
    if isinstance(outcome, Slither):
        return CompileResult(outcome, version, None, canonical, canonical)
    first_error = outcome

    fixes: set[str] = set()
    temp: Path | None = None
    error = first_error
    try:
        # Rungs a/c: apply every fix the latest error asks for that is not applied yet.
        while not ladder.exhausted:
            new_fixes = _fixes_for(error, has_pragma=bool(pragmas)) - fixes
            if not new_fixes:
                break
            fixes |= new_fixes
            temp = _temp_copy_path(canonical)
            try:
                temp.write_text(_apply_fixes(source, fixes), encoding="utf-8")
            except OSError as exc:
                ladder.log.append(f"could not write {temp.name}: {exc}")
                break
            outcome = ladder.attempt(temp, version)
            if isinstance(outcome, Slither):
                return CompileResult(outcome, version, _note(fixes, pragmas, version), temp, canonical)
            error = outcome
        # Rung b: no pragma -> older compilers, on the fixed copy if one was needed.
        if not pragmas:
            target = temp if temp is not None else canonical
            for older in NO_PRAGMA_LADDER:
                if ladder.exhausted:
                    break
                if older == version:
                    continue
                outcome = ladder.attempt(target, older)
                if isinstance(outcome, Slither):
                    return CompileResult(outcome, older, _note(fixes, pragmas, older), target, canonical)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
    raise CompileError(
        f"solc {version}: {first_error[:500]}\nretry ladder: " + " | ".join(ladder.log)
    )


def compile_file(path: Path) -> Slither:
    """Thin wrapper for callers that only need the Slither object.

    When the ladder rescued the file through a temp copy, filenames inside the returned Slither
    point at `<stem>.__relaxed__.sol`; use compile_file_ex(...).source_path to select contracts.
    """
    return compile_file_ex(path).slither
