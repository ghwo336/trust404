from __future__ import annotations

import csv
import re
import shutil
from pathlib import Path

import yaml

from .models import Case
from .validate import compile_case

PIED_PIPER_MAP = {
    "Arbitrary Transfer": "C",
    "Generate": "B",
    "Destroy": "B",
    "Generate/Destroy": "B",
    "Disable": "A",
    "Freeze": "A",
    "Disable/Freeze": "A",
}
CRPWARNER_MAP = {
    "Hidden Mint": "B",
    "Limiting Sell": "A",
    "Leaking": "C",
    "Leaking Token": "C",
}
HONEYBADGER_MAP = {"default": "F"}
SOURCE_MAPS = {
    "pied-piper": PIED_PIPER_MAP,
    "crpwarner": CRPWARNER_MAP,
    "honeybadger": HONEYBADGER_MAP,
}

ALLOWED_SOLC = ["0.4.26", "0.5.17", "0.6.12", "0.7.6", "0.8.20", "0.8.24"]
DEFAULT_SOLC = "0.8.20"
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]")
_VERDICTS = frozenset({"Benign", "Malicious", "Uncertain"})
_NON_COMPILE_NOTE = "non-compiling paper fixture"


def extract_pragma(sol_text: str) -> str:
    match = _PRAGMA_RE.search(sol_text)
    return match.group(1).strip() if match else ""


def _strip_pragma_prefix(pragma_or_version: str) -> str:
    text = pragma_or_version.strip()
    text = re.sub(r"^\s*pragma\s+solidity\s+", "", text, flags=re.IGNORECASE)
    return text.rstrip(";").strip()


def _same_minor(major: int, minor: int) -> list[str]:
    prefix = f"{major}.{minor}."
    return [ver for ver in ALLOWED_SOLC if ver.startswith(prefix)]


def _parse_triple(version: str) -> tuple[int, int, int]:
    major_s, minor_s, patch_s = version.split(".")
    return int(major_s), int(minor_s), int(patch_s)


def pin_solc(pragma_or_version: str) -> str:
    spec = _strip_pragma_prefix(pragma_or_version or "")
    if not spec:
        return DEFAULT_SOLC
    if _EXACT_VERSION_RE.fullmatch(spec):
        if spec in ALLOWED_SOLC:
            return spec
        major, minor, patch = _parse_triple(spec)
        same = _same_minor(major, minor)
        if not same:
            return DEFAULT_SOLC
        return min(
            same,
            key=lambda ver: (abs(_parse_triple(ver)[2] - patch), _parse_triple(ver)[2]),
        )
    match = _VERSION_RE.search(spec)
    if not match:
        return DEFAULT_SOLC
    major, minor = int(match.group(1)), int(match.group(2))
    same = _same_minor(major, minor)
    if not same:
        return DEFAULT_SOLC
    return same[-1]


def _slug(relative_path: str) -> str:
    return _NON_ALNUM_RE.sub("_", relative_path.replace("\\", "/"))


def _family_for(source: str, category: str) -> str | None:
    mapping = SOURCE_MAPS[source]
    if category in mapping:
        return mapping[category]
    return mapping.get("default")


def _append_note(notes: str, extra: str) -> str:
    extra = extra.strip()
    if not extra:
        return notes
    if not notes:
        return extra
    if extra in notes:
        return notes
    return f"{notes}; {extra}"


def _dump_labels(path: Path, payload: dict) -> None:
    cleaned = {key: value for key, value in payload.items() if value not in (None, "", [], ())}
    path.write_text(yaml.safe_dump(cleaned, sort_keys=False), encoding="utf-8")


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows: list[dict[str, str]] = []
        for raw in reader:
            if raw is None:
                continue
            row = { (key or "").strip(): (value or "").strip() for key, value in raw.items() }
            if not any(row.values()):
                continue
            rows.append(row)
        return rows


def _case_from_labels(
    dest_dir: Path,
    payload: dict,
    cases_root: Path,
) -> Case:
    preferred = payload["preferred_verdict"]
    accepted = tuple(payload["accepted_verdicts"])
    rel = dest_dir.relative_to(Path(cases_root))
    return Case(
        id=payload["id"],
        tier=rel.parts[0],
        dir=dest_dir,
        file=payload["file"],
        preferred_verdict=preferred,
        accepted_verdicts=accepted,
        expected_families=tuple(payload.get("expected_families") or ()),
        expected_rule_ids=tuple(payload.get("expected_rule_ids") or ()),
        expected_functions=tuple(payload.get("expected_functions") or ()),
        source=payload.get("source") or "",
        solc=payload.get("solc") or "",
        notes=payload.get("notes") or "",
    )


def ingest_paper(
    source: str,
    src_dir,
    cases_root,
    compile_check: bool = False,
    repo_root=None,
    dry_run: bool = False,
) -> list[str]:
    if source not in SOURCE_MAPS:
        valid = ", ".join(sorted(SOURCE_MAPS))
        raise ValueError(f"unknown source {source!r}; valid sources: {valid}")

    src_dir = Path(src_dir)
    cases_root = Path(cases_root)
    manifest = src_dir / "manifest.csv"
    if not manifest.is_file():
        raise FileNotFoundError(
            f"manifest.csv not found in {src_dir}; expected header file,category"
        )

    if compile_check and repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]
    else:
        repo_root = Path(repo_root) if repo_root is not None else None

    created: list[str] = []
    for row in _read_csv_rows(manifest):
        rel_file = row.get("file") or ""
        category = row.get("category") or ""
        if not rel_file:
            continue
        sol_path = src_dir / rel_file
        text = sol_path.read_text(encoding="utf-8")
        version = pin_solc(extract_pragma(text) or "")
        family = _family_for(source, category)
        notes = ""
        if family is None:
            notes = f"unknown category: {category}"
        slug = _slug(rel_file)
        case_id = f"tier2/{source}/{slug}"
        dest_dir = cases_root / source / slug
        sol_name = f"{slug}.sol"
        payload: dict = {
            "id": case_id,
            "file": sol_name,
            "preferred_verdict": "Malicious",
            "accepted_verdicts": ["Malicious"],
            "source": f"{source} manifest: {category}",
            "solc": version,
        }
        if family is not None:
            payload["expected_families"] = [family]
        if notes:
            payload["notes"] = notes

        created.append(case_id)
        if dry_run:
            continue

        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sol_path, dest_dir / sol_name)
        _dump_labels(dest_dir / "labels.yaml", payload)

        if compile_check:
            case = _case_from_labels(dest_dir, payload, cases_root)
            ok, _log = compile_case(case, repo_root)
            if not ok:
                payload["preferred_verdict"] = "Uncertain"
                payload["accepted_verdicts"] = ["Uncertain"]
                payload["notes"] = _append_note(payload.get("notes") or "", _NON_COMPILE_NOTE)
                _dump_labels(dest_dir / "labels.yaml", payload)

    return created


def _discord_label_map(src_dir: Path) -> dict[str, str]:
    labels_path = src_dir / "labels.csv"
    if not labels_path.is_file():
        return {}
    mapping: dict[str, str] = {}
    for row in _read_csv_rows(labels_path):
        rel_file = row.get("file") or ""
        verdict = row.get("verdict") or ""
        if not rel_file:
            continue
        if verdict not in _VERDICTS:
            raise ValueError(
                f"invalid verdict {verdict!r} for {rel_file!r}; "
                "expected Benign, Malicious, or Uncertain"
            )
        mapping[rel_file.replace("\\", "/")] = verdict
        mapping[Path(rel_file).name] = verdict
    return mapping


def ingest_discord(src_dir, cases_root, dry_run: bool = False) -> list[str]:
    src_dir = Path(src_dir)
    cases_root = Path(cases_root)
    label_map = _discord_label_map(src_dir)
    created: list[str] = []
    for sol_path in sorted(p for p in src_dir.rglob("*.sol") if p.is_file()):
        rel = sol_path.relative_to(src_dir).as_posix()
        slug = _slug(rel)
        case_id = f"tier0/{slug}"
        verdict = label_map.get(rel) or label_map.get(sol_path.name)
        text = sol_path.read_text(encoding="utf-8")
        version = pin_solc(extract_pragma(text) or "")
        sol_name = f"{slug}.sol"
        dest_dir = cases_root / slug
        payload: dict = {
            "id": case_id,
            "file": sol_name,
            "solc": version,
        }
        if verdict:
            payload["preferred_verdict"] = verdict
            payload["accepted_verdicts"] = [verdict]
        else:
            payload["preferred_verdict"] = "Uncertain"
            payload["accepted_verdicts"] = ["Benign", "Malicious", "Uncertain"]
            payload["notes"] = "TODO: set organizer label"

        created.append(case_id)
        if dry_run:
            continue
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sol_path, dest_dir / sol_name)
        _dump_labels(dest_dir / "labels.yaml", payload)
    return created
