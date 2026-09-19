from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import yaml
import jsonschema

SCHEMA_DIR = Path(__file__).with_name("schema")
VERDICTS = ("Benign", "Malicious", "Uncertain")


class SchemaError(ValueError):
    """Raised when a labels.yaml or results.json fails schema validation. Message must name the file/path and the JSON pointer of the failure."""


def load_schema(name: str) -> dict:
    path = SCHEMA_DIR / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate_against(schema_name: str, obj: dict, where: str = "<memory>") -> None:
    schema = load_schema(schema_name)
    validator = jsonschema.Draft202012Validator(schema)
    for err in validator.iter_errors(obj):
        raise SchemaError(f"{where}: {err.json_path}: {err.message}")


@dataclass(frozen=True)
class Case:
    id: str
    tier: str            # e.g. 'tier1_pairs' — the top-level dir name under cases_root
    dir: Path            # case directory containing labels.yaml
    file: str            # .sol filename relative to dir
    preferred_verdict: str
    accepted_verdicts: tuple[str, ...]
    expected_families: tuple[str, ...] = ()
    expected_rule_ids: tuple[str, ...] = ()
    expected_functions: tuple[str, ...] = ()
    source: str = ""
    solc: str = ""
    notes: str = ""

    @property
    def sol_path(self) -> Path:
        return self.dir / self.file

    @property
    def is_malicious(self) -> bool:
        return self.preferred_verdict == "Malicious"

    @property
    def is_benign(self) -> bool:
        return self.preferred_verdict == "Benign"

    @property
    def staged_file(self) -> str:
        """Path the tool must report for this case: '<case.id>/<case.file>' (POSIX separators)."""
        return f"{self.id}/{self.file}"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    family: str
    severity: str
    contract: str = ""
    function: str = ""
    lines: tuple[int, ...] = ()
    reasoning: str = ""


@dataclass(frozen=True)
class FileResult:
    file: str
    verdict: str
    reason: str = ""
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    tool_version: str
    results: tuple[FileResult, ...]

    def by_file(self) -> dict[str, FileResult]:
        out: dict[str, FileResult] = {}
        for r in self.results:
            key = normalize_result_file(r.file)
            if key not in out:
                out[key] = r
        return out


def normalize_result_file(path: str) -> str:
    """Normalize a tool-reported file path for matching: strip leading './', '/input/', 'input/'; convert backslashes to '/'; collapse duplicate slashes."""
    s = path.replace("\\", "/")
    prefixes = ("./", "/input/", "input/")
    changed = True
    while changed:
        changed = False
        for prefix in prefixes:
            if s.startswith(prefix):
                s = s[len(prefix) :]
                changed = True
                break
    while "//" in s:
        s = s.replace("//", "/")
    return s


def load_case(labels_path: Path, cases_root: Path) -> Case:
    labels_path = Path(labels_path)
    cases_root = Path(cases_root)
    data = yaml.safe_load(labels_path.read_text(encoding="utf-8"))
    validate_against("case", data, where=str(labels_path))
    preferred = data["preferred_verdict"]
    accepted = tuple(data["accepted_verdicts"])
    if preferred not in accepted:
        raise SchemaError(
            f"{labels_path}: $.preferred_verdict: {preferred!r} not in accepted_verdicts"
        )
    rel = labels_path.relative_to(cases_root)
    tier = rel.parts[0]
    return Case(
        id=data["id"],
        tier=tier,
        dir=labels_path.parent,
        file=data["file"],
        preferred_verdict=preferred,
        accepted_verdicts=accepted,
        expected_families=tuple(data.get("expected_families") or ()),
        expected_rule_ids=tuple(data.get("expected_rule_ids") or ()),
        expected_functions=tuple(data.get("expected_functions") or ()),
        source=data.get("source") or "",
        solc=data.get("solc") or "",
        notes=data.get("notes") or "",
    )


def _tier_matches(top: str, spec: str) -> bool:
    if spec.isdigit():
        return top.startswith(f"tier{spec}_")
    return top == spec


def load_cases(cases_root: str | Path, tiers: list[str] | None = None) -> list[Case]:
    cases_root = Path(cases_root)
    paths = sorted(cases_root.rglob("labels.yaml"))
    if tiers is not None:
        paths = [
            p
            for p in paths
            if any(_tier_matches(p.relative_to(cases_root).parts[0], spec) for spec in tiers)
        ]
    cases = [load_case(p, cases_root) for p in paths]
    seen: dict[str, Path] = {}
    for case in cases:
        if case.id in seen:
            raise SchemaError(f"{case.dir / 'labels.yaml'}: $.id: duplicate id {case.id!r}")
        seen[case.id] = case.dir
    return cases


def _finding_from_dict(obj: dict) -> Finding:
    return Finding(
        rule_id=obj["rule_id"],
        family=obj["family"],
        severity=obj["severity"],
        contract=obj.get("contract") or "",
        function=obj.get("function") or "",
        lines=tuple(obj.get("lines") or ()),
        reasoning=obj.get("reasoning") or "",
    )


def _file_result_from_dict(obj: dict) -> FileResult:
    findings = tuple(_finding_from_dict(f) for f in (obj.get("findings") or ()))
    return FileResult(
        file=obj["file"],
        verdict=obj["verdict"],
        reason=obj.get("reason") or "",
        findings=findings,
    )


def parse_result(obj_or_path: dict | str | Path, where: str | None = None) -> ToolResult:
    if isinstance(obj_or_path, dict):
        obj = obj_or_path
        loc = where or "<memory>"
    else:
        path = Path(obj_or_path)
        loc = where or str(path)
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SchemaError(f"{path}: JSON decode error: {exc}") from exc
    validate_against("result", obj, where=loc)
    tool = obj["tool"]
    results = tuple(_file_result_from_dict(r) for r in obj["results"])
    return ToolResult(
        tool_name=tool["name"],
        tool_version=tool.get("version") or "",
        results=results,
    )


def _omit_empty(d: dict) -> dict:
    return {k: v for k, v in d.items() if v not in ("", [], (), None)}


def result_to_dict(tr: ToolResult) -> dict:
    tool = _omit_empty({"name": tr.tool_name, "version": tr.tool_version})
    results = []
    for r in tr.results:
        item = _omit_empty(
            {
                "file": r.file,
                "verdict": r.verdict,
                "reason": r.reason,
                "findings": [
                    _omit_empty(
                        {
                            "rule_id": f.rule_id,
                            "family": f.family,
                            "severity": f.severity,
                            "contract": f.contract,
                            "function": f.function,
                            "lines": list(f.lines),
                            "reasoning": f.reasoning,
                        }
                    )
                    for f in r.findings
                ],
            }
        )
        results.append(item)
    return {"tool": tool, "results": results}
