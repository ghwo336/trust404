"""Solc selection, OpenZeppelin remapping, Slither construction, and the compile retry ladder."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import tempfile
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from slither import Slither
from solc_select.constants import ARTIFACTS_DIR as SOLC_SELECT_ARTIFACTS_DIR

logger = logging.getLogger(__name__)

INSTALLED_SOLC: tuple[str, ...] = tuple(
    line.strip()
    for line in Path(__file__).with_name("solc_versions.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
)
DEFAULT_SOLC = "0.8.20"
SOLC_ARTIFACTS_ENV = "DETECTOR_SOLC_ARTIFACTS"

# Retry ladder knobs (see docs/specs/detector.md, "Retry ladder").
MAX_SOLC_ATTEMPTS = 5
NO_PRAGMA_LADDER = ("0.4.26", "0.5.17", "0.6.12", "0.7.6")
RELAXED_PRAGMA = "pragma solidity >=0.4.0;"
TEMP_COPY_SUFFIX = ".__relaxed__.sol"
SCRATCH_ENV = "DETECTOR_SCRATCH_DIR"
SCRATCH_PREFIX = "detector-"
MIRROR_ROOT_NAME = "root"
_MIRROR_NAMES = frozenset({"remappings.txt", "foundry.toml", "package.json"})

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_CONSTRAINT_RE = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_SPDX_LINE_RE = re.compile(r"^[ \t]*//[ \t]*SPDX-License-Identifier:[^\n]*$", re.MULTILINE)
_SPDX_BLOCK_RE = re.compile(r"/\*[ \t]*SPDX-License-Identifier:[^*\n]*\*/")

_RELAX_MARKER = "requires different compiler version"
_SPDX_MARKER = "Multiple SPDX license identifiers"
_FIX_RELAX = "relax"
_FIX_SPDX = "spdx"
_FIX_BOM = "bom"
_IMPORT_RE = re.compile(r"""import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']""")

Version = tuple[int, int, int]
Constraint = tuple[str, Version]  # op in {">=", ">", "<=", "<", "="}


class CompileError(Exception):
    """Raised when solc is missing or Slither / crytic-compile fails."""


@dataclass(frozen=True)
class CompileResult:
    """A successful compile.

    `source_path` is the file Slither actually parsed: identical to `canonical_path` unless the
    retry ladder rewrote the source into a scratch-mirror copy (already deleted by the time this
    is returned; Slither caches source text at construction). Filenames inside `slither` point at
    `source_path`, so callers that filter contracts by file (engine.target_contracts) must pass
    `source_path`, not `canonical_path`. `note` is None when the first attempt succeeded.
    """

    slither: Slither
    version: str
    note: str | None
    source_path: Path
    canonical_path: Path
    oz_tag: str | None = None


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

    Parse every `pragma solidity` statement (AND across statements; `||` OR-ed inside one).
    Prefer DEFAULT_SOLC when it satisfies. Else among satisfying pins take the lowest
    satisfying minor (breaking changes land at minor boundaries) and the highest satisfying
    patch on that minor (features accrue inside a minor; `address[] calldata` needs 0.6.9+).
    Else the legacy nearest-same-minor of the first literal (unknown minor → DEFAULT_SOLC).
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
            def rank(ver: str) -> tuple[int, int, int]:
                major, minor, patch = _ver_tuple(ver)
                return (major, minor, -patch)

            return min(satisfying, key=rank)
    found = _VERSION_RE.findall(exprs[0])
    if not found:
        return DEFAULT_SOLC
    return _nearest_same_minor(_ver_tuple(found[0]))


def solc_artifact_roots() -> list[Path]:
    override = os.environ.get(SOLC_ARTIFACTS_ENV, "").strip()
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override))
    candidates.append(SOLC_SELECT_ARTIFACTS_DIR)
    candidates.append(Path.home() / ".solc-select" / "artifacts")
    roots: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        roots.append(path)
    return roots


def solc_binary(version: str) -> Path:
    roots = solc_artifact_roots()
    rel = Path(f"solc-{version}") / f"solc-{version}"
    for root in roots:
        candidate = root / rel
        if candidate.is_file():
            return candidate
    return roots[0] / rel


OZ_DIR_ENV = "DETECTOR_OZ_DIR"
OZ_V5_DIR_ENV = "DETECTOR_OZ_V5_DIR"
_OZ_IMPORT_PREFIX = "@openzeppelin/contracts/"


def _oz_tree_dir(env_name: str, vendor_name: str) -> Path | None:
    env = os.environ.get(env_name)
    if env is not None and not env.strip():
        return None
    candidates: list[Path] = []
    if env:
        candidates.append(Path(env))
    repo = Path(__file__).resolve().parents[1]
    candidates.append(repo / "vendor" / vendor_name)
    candidates.append(Path("/app/vendor") / vendor_name)
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def oz_trees() -> list[tuple[str, Path]]:
    trees: list[tuple[str, Path]] = []
    v4 = _oz_tree_dir(OZ_DIR_ENV, "openzeppelin-contracts")
    if v4 is not None:
        trees.append(("v4", v4))
    v5 = _oz_tree_dir(OZ_V5_DIR_ENV, "openzeppelin-contracts-v5")
    if v5 is not None:
        trees.append(("v5", v5))
    return trees


def oz_remapping(tree: Path | None = None) -> str | None:
    vendor = tree
    if vendor is None:
        vendor = next((path for tag, path in oz_trees() if tag == "v4"), None)
    if vendor is None:
        return None
    return f"@openzeppelin/contracts/={vendor.as_posix()}/"


def rank_oz_trees(source: str, trees: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    rels = [
        spec[len(_OZ_IMPORT_PREFIX) :]
        for spec in _imported_specs(source)
        if spec.startswith(_OZ_IMPORT_PREFIX)
    ]
    if not rels:
        return list(trees)

    def score(item: tuple[str, Path]) -> tuple[int, int]:
        _tag, path = item
        resolved = sum(1 for rel in rels if (path / rel).is_file())
        all_resolve = 1 if resolved == len(rels) else 0
        return (-all_resolve, -resolved)

    return sorted(trees, key=score)


def _parse_remap_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    prefix, target = stripped.split("=", 1)
    prefix, target = prefix.strip(), target.strip()
    if not prefix or not target:
        return None
    return prefix, target


def _abs_remap_target(root: Path, target: str) -> str:
    raw = target.strip()
    path = Path(raw)
    resolved = path.resolve() if path.is_absolute() else (root / raw).resolve()
    text = resolved.as_posix()
    if (raw.endswith("/") or resolved.is_dir()) and not text.endswith("/"):
        text += "/"
    return text


def _dir_remap_target(directory: Path) -> str:
    text = directory.resolve().as_posix()
    return text if text.endswith("/") else f"{text}/"


def _parse_foundry_remappings(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    entries: list[str] = []
    raw = data.get("remappings")
    if isinstance(raw, list):
        entries.extend(str(item) for item in raw)
    profiles = data.get("profile")
    if isinstance(profiles, dict):
        for _name, section in sorted(profiles.items(), key=lambda item: str(item[0])):
            if isinstance(section, dict) and isinstance(section.get("remappings"), list):
                entries.extend(str(item) for item in section["remappings"])
    return entries


def _project_remappings(root: Path) -> list[tuple[str, str]]:
    lines: list[str] = []
    txt = root / "remappings.txt"
    if txt.is_file():
        try:
            lines.extend(txt.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            pass
    lines.extend(_parse_foundry_remappings(root / "foundry.toml"))
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for line in lines:
        parsed = _parse_remap_line(line)
        if parsed is None or parsed[0] in seen:
            continue
        prefix, target = parsed
        seen.add(prefix)
        out.append((prefix, _abs_remap_target(root, target)))
    return out


def _imported_specs(source: str) -> list[str]:
    return sorted(set(_IMPORT_RE.findall(source)))


def _covers(prefix: str, spec: str) -> bool:
    if spec.startswith(prefix):
        return True
    return not prefix.endswith("/") and (spec == prefix or spec.startswith(f"{prefix}/"))


def _any_covers(prefixes: list[str], spec: str) -> bool:
    return any(_covers(prefix, spec) for prefix in prefixes)


def _auto_remap_for_spec(root: Path, spec: str) -> tuple[str, str] | None:
    if spec.startswith("./") or spec.startswith("../"):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        if len(parts) < 2:
            return None
        package = root / "node_modules" / parts[0] / parts[1]
        if package.is_dir():
            return f"{parts[0]}/{parts[1]}/", _dir_remap_target(package)
        return None
    name = spec.split("/", 1)[0]
    if not name:
        return None
    node_pkg = root / "node_modules" / name
    if node_pkg.is_dir():
        return f"{name}/", _dir_remap_target(node_pkg)
    lib = root / "lib" / name
    if not lib.is_dir():
        return None
    contracts, src = lib / "contracts", lib / "src"
    if spec.startswith(f"{name}/contracts/") and contracts.is_dir():
        return f"{name}/contracts/", _dir_remap_target(contracts)
    if spec.startswith(f"{name}/src/") and src.is_dir():
        return f"{name}/src/", _dir_remap_target(src)
    return f"{name}/", _dir_remap_target(lib)


def _allow_entries(path: Path) -> list[str]:
    raw = str(path)
    resolved = str(path.resolve())
    return [raw] if raw == resolved else [raw, resolved]


def _resolve_compile_paths(
    root: Path, source: str, oz: Path | None
) -> tuple[list[str], list[str]]:
    """Project remaps, then imported auto-maps, then the chosen OZ remap; first prefix wins."""
    pairs = list(_project_remappings(root))
    prefixes = [prefix for prefix, _target in pairs]
    for spec in _imported_specs(source):
        if _any_covers(prefixes, spec):
            continue
        auto = _auto_remap_for_spec(root, spec)
        if auto is None:
            continue
        pairs.append(auto)
        prefixes.append(auto[0])
    oz_remap = oz_remapping(oz) if oz is not None else None
    if oz_remap is not None:
        prefix, _, target = oz_remap.partition("=")
        if not _any_covers(prefixes, prefix):
            pairs.append((prefix, target if target.endswith("/") else f"{target}/"))
    pairs.sort(key=lambda item: (-len(item[0]), item[0]))
    remaps = [f"{prefix}={target}" for prefix, target in pairs]
    allow: list[str] = []
    seen: set[str] = set()
    for _prefix, target in pairs:
        for entry in _allow_entries(Path(target.rstrip("/"))):
            if entry not in seen:
                seen.add(entry)
                allow.append(entry)
    return remaps, allow


# --- retry ladder -----------------------------------------------------------------------------


def is_temp_copy(path: Path) -> bool:
    """True for leftover `<stem>.__relaxed__.sol` names (the ladder no longer creates these)."""
    return Path(path).name.endswith(TEMP_COPY_SUFFIX)


def _temp_copy_path(canonical: Path) -> Path:
    return canonical.with_name(canonical.stem + TEMP_COPY_SUFFIX)


def _mirror_key(canonical: Path) -> str:
    return hashlib.sha1(str(canonical).encode()).hexdigest()[:16]


def scratch_mirror_dir(path: Path) -> Path | None:
    """Per-file mirror directory under `$DETECTOR_SCRATCH_DIR`, or None when the env var is unset."""
    env = os.environ.get(SCRATCH_ENV)
    if not env:
        return None
    return Path(env) / _mirror_key(Path(path).resolve())


def _safe_unlink(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except OSError:
        return False


def _safe_rmtree(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        if not path.exists():
            return False
        shutil.rmtree(path)
        return True
    except OSError:
        return False


def cleanup_temp_copies(path: Path) -> list[Path]:
    """Remove leftovers a killed worker left: a sibling `__relaxed__` copy and this file's scratch mirror."""
    removed: list[Path] = []
    canonical = Path(path).resolve()
    sibling = _temp_copy_path(canonical)
    try:
        sibling_exists = sibling.is_file()
    except OSError:
        sibling_exists = False
    if sibling_exists and _safe_unlink(sibling):
        removed.append(sibling)
    mirror = scratch_mirror_dir(canonical)
    if mirror is not None and _safe_rmtree(mirror):
        removed.append(mirror)
    return removed


@contextmanager
def scratch_session() -> Iterator[Path | None]:
    """Own a `$DETECTOR_SCRATCH_DIR` for the batch (no-op when the parent already set one)."""
    previous = os.environ.get(SCRATCH_ENV)
    if previous:
        yield Path(previous)
        return
    created = None
    try:
        try:
            created = tempfile.mkdtemp(prefix=SCRATCH_PREFIX)
        except OSError as exc:
            logger.warning(
                "scratch dir unavailable (%s); ladder rewrite rungs disabled for this run",
                exc,
            )
            yield None
            return
        os.environ[SCRATCH_ENV] = created
        yield Path(created)
    finally:
        if created is not None:
            try:
                shutil.rmtree(created, ignore_errors=True)
            except OSError:
                pass
            os.environ.pop(SCRATCH_ENV, None)


def _should_mirror_file(path: Path) -> bool:
    if is_temp_copy(path):
        return False
    if path.suffix == ".sol":
        return True
    return path.name in _MIRROR_NAMES


def _link_or_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    try:
        os.link(src, dest)
    except OSError:
        shutil.copy2(src, dest)


def _mirror_input_root(input_root: Path, mirror_root: Path, skip: Path) -> None:
    """Hard-link or copy readable project files into `mirror_root`; never write a symlink."""
    skip_resolved = skip.resolve()
    seen: set[str] = set()
    stack = [input_root]
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
            try:
                if child.is_dir():
                    stack.append(child)
                    continue
                if not child.is_file() or not _should_mirror_file(child):
                    continue
            except OSError:
                continue
            try:
                if child.resolve() == skip_resolved:
                    continue
            except OSError:
                pass
            try:
                rel = child.relative_to(input_root)
            except ValueError:
                continue
            _link_or_copy(child, mirror_root / rel)


def _write_rewritten(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    _safe_unlink(dest)
    dest.write_text(text, encoding="utf-8")


def _ensure_scratch_root() -> tuple[Path, Path | None]:
    env = os.environ.get(SCRATCH_ENV)
    if env:
        root = Path(env)
        root.mkdir(parents=True, exist_ok=True)
        return root, None
    created = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX))
    return created, created


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
    if _FIX_BOM in fixes:
        source = source.removeprefix("\ufeff")
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


def _note(
    fixes: set[str], pragmas: list[str], version: str, oz_tag: str | None = None
) -> str:
    parts: list[str] = []
    if _FIX_BOM in fixes:
        parts.append("BOM stripped")
    if _FIX_RELAX in fixes:
        distinct = list(dict.fromkeys(pragmas))
        parts.append(f"pragma {' & '.join(distinct)} relaxed")
    if _FIX_SPDX in fixes:
        parts.append("duplicate SPDX identifiers removed")
    if not pragmas:
        parts.append("no pragma")
    if oz_tag:
        parts.append(f"oz={oz_tag}")
    parts.append(f"compiled with {version}")
    return "; ".join(parts)


def _newest_installed_08() -> str:
    return max(
        (ver for ver in INSTALLED_SOLC if _ver_tuple(ver)[:2] == (0, 8)),
        key=_ver_tuple,
    )


def _error_names_oz_tree(error: str, oz: Path | None) -> bool:
    if oz is None or not error:
        return False
    resolved = oz.resolve()
    for text in (str(resolved), resolved.as_posix(), str(oz), oz.as_posix()):
        if text and text in error:
            return True
    return "@openzeppelin/contracts" in error


def _has_oz_import(source: str) -> bool:
    return any(spec.startswith("@openzeppelin/") for spec in _imported_specs(source))


def _build_slither(
    target: Path,
    version: str,
    allow_root: Path,
    remaps: list[str],
    extra_allow: list[str],
    oz: Path | None,
) -> Slither:
    solc_bin = solc_binary(version)
    if not solc_bin.is_file():
        raise CompileError(f"solc {version}: binary not found at {solc_bin}")
    allow_parts: list[str] = []
    seen: set[str] = set()
    for part in (str(allow_root), *extra_allow):
        if part not in seen:
            seen.add(part)
            allow_parts.append(part)
    if oz is not None:
        oz_s = str(oz.resolve())
        if oz_s not in seen:
            allow_parts.append(oz_s)
    return Slither(
        str(target),
        solc=str(solc_bin),
        solc_remaps=remaps,
        solc_args=f"--allow-paths {','.join(allow_parts)}",
    )


class _Ladder:
    """Bounded sequence of Slither constructions for one file; records an attempt log."""

    def __init__(
        self,
        canonical: Path,
        allow_root: Path,
        remaps: list[str],
        extra_allow: list[str],
        oz: Path | None,
    ) -> None:
        self.canonical = canonical
        self.allow_root = allow_root
        self.remaps = remaps
        self.extra_allow = extra_allow
        self.oz = oz
        self.log: list[str] = []

    @property
    def exhausted(self) -> bool:
        return len(self.log) >= MAX_SOLC_ATTEMPTS

    def attempt(self, target: Path, version: str) -> Slither | str:
        """Return a Slither on success, else the error text."""
        try:
            slither = _build_slither(
                target, version, self.allow_root, self.remaps, self.extra_allow, self.oz
            )
        except CompileError as exc:  # missing binary: recorded, does not spawn solc
            self.log.append(f"{version} on {target.name}: {exc}")
            return str(exc)
        except Exception as exc:
            error = str(exc)
            self.log.append(f"{version} on {target.name}: {_first_error_line(error)}")
            return error
        self.log.append(f"{version} on {target.name}: ok")
        return slither


class _Scratch:
    """Lazy per-file scratch mirror of `allow_root`; created only when a rewrite rung runs."""

    def __init__(self, canonical: Path, allow_root: Path, source: str, oz: Path | None) -> None:
        self.canonical = canonical
        self.allow_root = allow_root
        self.source = source
        self.oz = oz
        self.owned_scratch: Path | None = None
        self.mirror_dir: Path | None = None
        self.mirror_root: Path | None = None
        self.mirror_target: Path | None = None

    def close(self) -> None:
        _safe_rmtree(self.mirror_dir)
        if self.owned_scratch is not None:
            _safe_rmtree(self.owned_scratch)
            self.owned_scratch = None
        self.mirror_dir = None

    def prepare(self, ladder: _Ladder, fixes: set[str]) -> Path:
        if self.mirror_target is None:
            scratch, owned = _ensure_scratch_root()
            self.owned_scratch = owned
            self.mirror_dir = scratch / _mirror_key(self.canonical)
            self.mirror_root = self.mirror_dir / MIRROR_ROOT_NAME
            try:
                rel = self.canonical.relative_to(self.allow_root)
            except ValueError:
                rel = Path(self.canonical.name)
            self.mirror_target = self.mirror_root / rel
            _mirror_input_root(self.allow_root, self.mirror_root, skip=self.canonical)
            remaps, extra_allow = _resolve_compile_paths(self.mirror_root, self.source, self.oz)
            ladder.allow_root = self.mirror_root
            ladder.remaps = remaps
            ladder.extra_allow = extra_allow
        _write_rewritten(self.mirror_target, _apply_fixes(self.source, fixes))
        return self.mirror_target


def _climb_ladder(
    ladder: _Ladder,
    canonical: Path,
    pragmas: list[str],
    version: str,
    first_error: str,
    fixes: set[str],
    scratch: _Scratch,
    *,
    oz: Path | None,
    oz_tag: str | None,
) -> CompileResult | None:
    """Rewrite rungs write into a scratch mirror of the input root, never into the input itself."""
    error = first_error
    fixes = set(fixes)
    fixes |= _fixes_for(error, has_pragma=bool(pragmas))
    applied: set[str] = set()
    target = canonical
    oz_switched = False
    while not ladder.exhausted:
        if (
            not oz_switched
            and oz is not None
            and _RELAX_MARKER in error
            and _error_names_oz_tree(error, oz)
        ):
            newest = _newest_installed_08()
            if newest != version:
                version = newest
                oz_switched = True
                outcome = ladder.attempt(target, version)
                if isinstance(outcome, Slither):
                    return CompileResult(
                        outcome,
                        version,
                        _note(applied, pragmas, version, oz_tag),
                        target,
                        canonical,
                        oz_tag,
                    )
                error = outcome
                fixes |= _fixes_for(error, has_pragma=bool(pragmas))
                continue
        if not (fixes - applied):
            break
        try:
            target = scratch.prepare(ladder, fixes)
        except OSError as exc:
            ladder.log.append(f"no scratch: {exc}")
            break
        applied = set(fixes)
        outcome = ladder.attempt(target, version)
        if isinstance(outcome, Slither):
            return CompileResult(
                outcome,
                version,
                _note(fixes, pragmas, version, oz_tag),
                target,
                canonical,
                oz_tag,
            )
        error = outcome
        fixes |= _fixes_for(error, has_pragma=bool(pragmas))
    if not pragmas:
        fallback = canonical
        try:
            if scratch.mirror_target is not None and scratch.mirror_target.is_file():
                fallback = scratch.mirror_target
        except OSError:
            fallback = canonical
        for older in NO_PRAGMA_LADDER:
            if ladder.exhausted:
                break
            if older == version:
                continue
            outcome = ladder.attempt(fallback, older)
            if isinstance(outcome, Slither):
                return CompileResult(
                    outcome,
                    older,
                    _note(fixes, pragmas, older, oz_tag),
                    fallback,
                    canonical,
                    oz_tag,
                )
    return None


def compile_file_ex(path: Path, *, input_root: Path | None = None) -> CompileResult:
    """Compile `path` with pick_solc's version, then climb the retry ladder on failure.

    `input_root` is the directory given to the CLI (allow-paths + remappings). Tests that call
    `compile_file(path)` omit it; then allow-paths defaults to the file's parent as before.

    Ladder (each rung is a fresh Slither construction; at most MAX_SOLC_ATTEMPTS per OZ tree):
      a. error says "requires different compiler version" -> scratch-mirror rewrite with every
         `pragma solidity` statement replaced by RELAXED_PRAGMA, same version;
      b. no pragma and the default fails -> NO_PRAGMA_LADDER versions in order;
      c. error says "Multiple SPDX license identifiers" -> scratch-mirror rewrite with all but
         the first SPDX comment blanked (combined with a. when both apply);
      BOM. source starts with a UTF-8 BOM -> scratch-mirror rewrite with the BOM stripped;
      OZ-version: error names a path under the current OZ tree and says
         "requires different compiler version" -> newest installed 0.8.x, then (a) if needed;
      e. the whole ladder for the next ranked OZ tree (`oz <tag> failed: …`);
      d. anything else -> CompileError carrying the ORIGINAL first error plus the attempt log.
    Rewrites preserve line numbers. The input root is never written; the mirror is deleted
    before returning or raising. A file whose first attempt compiles never creates a mirror.
    """
    canonical = Path(path).resolve()
    allow_root = Path(input_root).resolve() if input_root is not None else canonical.parent
    source = canonical.read_text(encoding="utf-8", errors="replace")
    pragmas = _pragma_exprs(source)
    version_picked = pick_solc(source)
    if not solc_binary(version_picked).is_file():
        raise CompileError(
            f"solc {version_picked}: binary not found at {solc_binary(version_picked)}"
        )

    has_oz = _has_oz_import(source)
    ranked = rank_oz_trees(source, oz_trees())
    if not ranked:
        worklist: list[tuple[str | None, Path | None]] = [(None, None)]
    elif has_oz:
        worklist = list(ranked)
    else:
        worklist = [ranked[0]]

    combined_log: list[str] = []
    first_error_overall = ""
    first_version = version_picked

    for tree_index, (tag, tree) in enumerate(worklist):
        remaps, extra_allow = _resolve_compile_paths(allow_root, source, tree)
        version = version_picked
        ladder = _Ladder(canonical, allow_root, remaps, extra_allow, tree)
        scratch = _Scratch(canonical, allow_root, source, tree)
        first_error = ""
        try:
            outcome = ladder.attempt(canonical, version)
            if isinstance(outcome, Slither):
                oz_tag = tag if has_oz else None
                note: str | None = None
                if has_oz and tag is not None and (tree_index > 0 or tag != "v4"):
                    note = f"oz={tag}"
                return CompileResult(outcome, version, note, canonical, canonical, oz_tag)
            first_error = outcome
            if not first_error_overall:
                first_error_overall = first_error
            fixes: set[str] = set()
            if source.startswith("\ufeff"):
                fixes.add(_FIX_BOM)
            rescued = _climb_ladder(
                ladder,
                canonical,
                pragmas,
                version,
                first_error,
                fixes,
                scratch,
                oz=tree,
                oz_tag=tag if has_oz else None,
            )
            if rescued is not None:
                return rescued
        finally:
            scratch.close()
        combined_log.extend(ladder.log)
        if tree_index + 1 < len(worklist):
            label = tag if tag is not None else "none"
            combined_log.append(f"oz {label} failed: {_first_error_line(first_error)}")

    raise CompileError(
        f"solc {first_version}: {first_error_overall[:500]}\nretry ladder: "
        + " | ".join(combined_log)
    )


def compile_file(path: Path, *, input_root: Path | None = None) -> Slither:
    """Thin wrapper for callers that only need the Slither object.

    When the ladder rescued the file through a scratch-mirror rewrite, filenames inside the
    returned Slither point at the mirror path; use compile_file_ex(...).source_path to select
    contracts.
    """
    return compile_file_ex(path, input_root=input_root).slither
