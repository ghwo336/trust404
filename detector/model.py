"""Finding / FileResult dataclasses and canonical results.json writer."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

from jsonschema.validators import Draft202012Validator

from detector import TOOL_NAME, TOOL_VERSION

Severity = Literal["HIGH", "MED", "INFO"]
Verdict = Literal["Benign", "Malicious", "Uncertain"]
Family = Literal["A", "B", "C", "D", "E", "F", "G"]

_SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "result.schema.json"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    family: str
    severity: str
    contract: str = ""
    function: str = ""
    lines: tuple[int, ...] = ()
    reasoning: str = ""
    base_severity: str = ""
    discriminators: tuple[str, ...] = ()
    counts_for_escalation: bool = True

    def to_json(self) -> dict:
        obj: dict = {
            "rule_id": self.rule_id,
            "family": self.family,
            "severity": self.severity,
        }
        if self.contract:
            obj["contract"] = self.contract
        if self.function:
            obj["function"] = self.function
        if self.lines:
            obj["lines"] = list(self.lines)
        if self.reasoning:
            obj["reasoning"] = self.reasoning
        return obj


@dataclass(frozen=True)
class FileResult:
    file: str
    verdict: str
    reason: str = ""
    findings: tuple[Finding, ...] = ()

    def to_json(self) -> dict:
        obj: dict = {
            "file": self.file,
            "verdict": self.verdict,
            "findings": [finding.to_json() for finding in self.findings],
        }
        if self.reason:
            obj["reason"] = self.reason
        return obj


def canonical_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    return tuple(sorted(findings, key=lambda f: (f.rule_id, f.contract, f.function, f.lines)))


def build_output(results: Iterable[FileResult]) -> dict:
    ordered = []
    for result in sorted(results, key=lambda item: item.file):
        ordered.append(
            FileResult(
                file=result.file,
                verdict=result.verdict,
                reason=result.reason,
                findings=canonical_findings(result.findings),
            ).to_json()
        )
    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "results": ordered,
    }


def validate_output(obj: dict) -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    for err in validator.iter_errors(obj):
        raise ValueError(f"{err.json_path}: {err.message}")


def write_results(path: Path, results: list[FileResult]) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    obj = build_output(results)
    validate_output(obj)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return obj
