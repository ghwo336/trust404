"""Submission adapter: judge schema objects, walk, budget, CLI stdout, run.sh, docker_entry."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from detector import docker_entry
from detector.describe import (
    REASON_SENTENCES,
    bounding_notes,
    governance_notes,
    rule_explanation,
    rule_title,
)
from detector.engine import analyze_file
from detector.model import FileResult, Finding
from detector.submission import (
    list_top_level_sol,
    run_submission,
    to_judge_object,
    validate_against_schema,
)
from tests.detector.conftest import REPO_ROOT

TIER0 = REPO_ROOT / "cases" / "tier0_judge"
JUDGE_SCHEMA_SRC = REPO_ROOT / "docs" / "judge" / "challenge_public" / "schema.json"
JUDGE_SCHEMA_DST = REPO_ROOT / "detector" / "schema" / "judge.schema.json"

BENIGN_NO_FINDINGS = (
    "no privileged writer of balances, exit gates, fees or value sinks; "
    "no delegatecall/selfdestruct escape hatch"
)
BENIGN_BOUNDED = (
    "privileged controls present but every one is bounded in code or off the transfer path; "
    "no unbounded privileged path to user assets"
)
BUDGET_REASON = "global time budget exhausted before this file was analysed"


def _sol(tmp_path: Path, name: str = "Sample.sol", n_lines: int = 10) -> Path:
    path = tmp_path / name
    path.write_text(
        "\n".join(f"// line {i}" for i in range(1, n_lines + 1)) + "\n",
        encoding="utf-8",
    )
    return path


def _flat_tier0(tmp_path: Path) -> Path:
    dest = tmp_path / "in"
    dest.mkdir()
    for src in sorted(TIER0.glob("*/*.sol")):
        shutil.copy2(src, dest / src.name)
    return dest


def _finding(
    rule_id: str,
    *,
    family: str = "A",
    severity: str = "HIGH",
    function: str = "setFlag",
    lines: tuple[int, ...] = (3,),
    reasoning: str = "owner writes the gate that blocks transfer",
    contract: str = "Token",
    discriminators: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        family=family,
        severity=severity,
        contract=contract,
        function=function,
        lines=lines,
        reasoning=reasoning,
        discriminators=discriminators,
    )


def test_judge_schema_is_verbatim_copy() -> None:
    assert JUDGE_SCHEMA_DST.read_bytes() == JUDGE_SCHEMA_SRC.read_bytes()


def test_to_judge_object_malicious_schema_and_mapping(tmp_path: Path) -> None:
    source = _sol(tmp_path, "Rug.sol", n_lines=10)
    result = FileResult(
        file="ignored/Rug.sol",
        verdict="Malicious",
        findings=(
            _finding("EXIT_ADDR_GATE", family="A", lines=(999,)),
            _finding(
                "OWN_HIDDEN_ROLE",
                family="D",
                function="hiddenAdmin",
                lines=(4,),
                reasoning="undisclosed auth var gates mint",
            ),
        ),
    )
    obj = to_judge_object(result, source)
    validate_against_schema([obj])
    assert obj["file"] == "Rug.sol"
    assert obj["verdict"] == "MALICIOUS"
    assert obj["evidence"], "MALICIOUS must carry evidence"
    assert obj["evidence"][0]["line"] == 10
    assert 1 <= obj["evidence"][0]["line"] <= 10
    assert obj["risk_level"] == "CRITICAL"
    assert obj["risk_type"] == "BACKDOOR"
    assert obj["confidence"] == 0.9
    assert obj["reasons"]
    assert rule_title("EXIT_ADDR_GATE") in obj["reasons"][0]
    assert "owner writes the gate that blocks transfer" in obj["reasons"][0]
    assert rule_explanation("EXIT_ADDR_GATE") in obj["reasons"][0]


def test_to_judge_object_malicious_slither_only_is_vulnerability(tmp_path: Path) -> None:
    source = _sol(tmp_path, "Reent.sol")
    result = FileResult(
        file="Reent.sol",
        verdict="Malicious",
        findings=(
            _finding(
                "SLITHER_HIGH_OVERLAY",
                family="C",
                function="withdraw",
                lines=(2,),
                reasoning="reentrancy-eth on withdraw",
            ),
        ),
    )
    obj = to_judge_object(result, source)
    validate_against_schema([obj])
    assert obj["verdict"] == "MALICIOUS"
    assert obj["risk_level"] == "HIGH"
    assert obj["risk_type"] == "VULNERABILITY"
    assert obj["confidence"] == 0.8
    assert obj["evidence"]


def test_to_judge_object_benign_no_findings(tmp_path: Path) -> None:
    source = _sol(tmp_path, "Plain.sol")
    result = FileResult(file="Plain.sol", verdict="Benign")
    obj = to_judge_object(result, source)
    validate_against_schema([obj])
    assert obj["file"] == "Plain.sol"
    assert obj["verdict"] == "BENIGN"
    assert obj["reasons"] == [BENIGN_NO_FINDINGS]
    assert obj["evidence"] == []
    assert "risk_level" not in obj
    assert obj["risk_type"] == "NONE"
    assert obj["confidence"] == 0.85


def test_to_judge_object_benign_info_only_with_discriminators(tmp_path: Path) -> None:
    source = _sol(tmp_path, "Capped.sol")
    result = FileResult(
        file="Capped.sol",
        verdict="Benign",
        findings=(
            _finding(
                "BAL_PRIV_MINT",
                family="B",
                severity="INFO",
                function="mint",
                lines=(5,),
                reasoning="owner mint bounded by cap",
                discriminators=("constant_cap", "managed_role"),
            ),
        ),
    )
    obj = to_judge_object(result, source)
    validate_against_schema([obj])
    assert obj["verdict"] == "BENIGN"
    assert obj["reasons"][0] == BENIGN_BOUNDED
    assert any("owner mint bounded by cap" in row for row in obj["reasons"][1:])
    mint_row = next(row for row in obj["reasons"] if "owner mint bounded by cap" in row)
    for note in bounding_notes(result.findings[0]):
        assert f"(bounded: {note})" in mint_row
    for note in governance_notes(result.findings[0]):
        assert f"(governance: {note})" in mint_row
    assert obj["risk_level"] == "LOW"
    assert obj["risk_type"] == "CENTRALIZATION"
    assert obj["confidence"] == 0.7


def test_to_judge_object_uncertain_reason_sentence_first(tmp_path: Path) -> None:
    source = _sol(tmp_path, "Broken.sol")
    result = FileResult(
        file="Broken.sol",
        verdict="Uncertain",
        reason="compile_failed",
        findings=(
            _finding(
                "PRIV_ROLE",
                severity="INFO",
                function="setOwner",
                lines=(1,),
                reasoning="auth atom on owner",
            ),
        ),
    )
    obj = to_judge_object(result, source)
    validate_against_schema([obj])
    assert obj["verdict"] == "UNCERTAIN"
    assert obj["reasons"][0] == REASON_SENTENCES.get("compile_failed", "compile failed")
    assert any("auth atom on owner" in row for row in obj["reasons"][1:])
    assert obj["risk_level"] == "MEDIUM"
    assert "risk_type" not in obj
    assert obj["confidence"] == 0.3


def test_to_judge_object_uncertain_unknown_reason_is_humanised(tmp_path: Path) -> None:
    source = _sol(tmp_path, "Maybe.sol")
    result = FileResult(file="Maybe.sol", verdict="Uncertain", reason="brand_new_token")
    obj = to_judge_object(result, source)
    validate_against_schema([obj])
    assert obj["reasons"][0] == "brand new token"
    assert obj["reasons"][0]


def test_to_judge_object_one_reason_per_rule_two_evidence_rows(tmp_path: Path) -> None:
    source = _sol(tmp_path, "Gates.sol")
    result = FileResult(
        file="Gates.sol",
        verdict="Malicious",
        findings=(
            _finding("EXIT_ADDR_GATE", function="setBot", lines=(2,), reasoning="writer"),
            _finding("EXIT_ADDR_GATE", function="transfer", lines=(9,), reasoning="impact"),
        ),
    )
    obj = to_judge_object(result, source)
    validate_against_schema([obj])
    assert len(obj["reasons"]) == 1
    assert "writer" in obj["reasons"][0]
    assert {item["function"] for item in obj["evidence"]} == {"setBot", "transfer"}


def test_list_top_level_sol_non_recursive_and_recursive(tmp_path: Path) -> None:
    (tmp_path / "a.sol").write_text("// a\n", encoding="utf-8")
    (tmp_path / "b.sol").write_text("// b\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.sol").write_text("// c\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignore\n", encoding="utf-8")

    top = list_top_level_sol(tmp_path)
    assert [p.name for p in top] == ["a.sol", "b.sol"]
    assert all(p.parent == tmp_path for p in top)

    rec = list_top_level_sol(tmp_path, recursive=True)
    assert {p.name for p in rec} == {"a.sol", "b.sol", "c.sol"}


def test_run_submission_budget_emits_uncertain_for_remaining(tmp_path, monkeypatch) -> None:
    (tmp_path / "a.sol").write_text("// a\n", encoding="utf-8")
    (tmp_path / "b.sol").write_text("// b\n", encoding="utf-8")
    (tmp_path / "c.sol").write_text("// c\n", encoding="utf-8")

    def fake_analyze(path, rel, *, timeout_s, input_root):
        return FileResult(file=rel, verdict="Benign")

    monkeypatch.setattr("detector.submission.analyze_file", fake_analyze)

    calls = {"n": 0}

    def fake_now() -> float:
        calls["n"] += 1
        if calls["n"] <= 2:
            return 0.0
        return 10_000.0

    objs = run_submission(
        tmp_path,
        timeout_s=30,
        budget_s=10.0,
        recursive=False,
        now=fake_now,
    )
    assert len(objs) == 3
    assert objs[0]["file"] == "a.sol"
    assert objs[0]["verdict"] == "BENIGN"
    assert objs[1]["verdict"] == "UNCERTAIN"
    assert objs[1]["reasons"] == [BUDGET_REASON]
    assert objs[1]["risk_type"] == "NONE"
    assert objs[1]["confidence"] == 0.0
    assert objs[2]["verdict"] == "UNCERTAIN"
    assert objs[2]["reasons"] == [BUDGET_REASON]


def test_run_submission_empty_dir_returns_empty_array(tmp_path: Path) -> None:
    assert run_submission(tmp_path, timeout_s=10, budget_s=30.0, recursive=False) == []


def test_cli_submission_tier0_stdout_is_schema_valid(tmp_path: Path) -> None:
    dest = _flat_tier0(tmp_path)
    names = sorted(p.name for p in dest.glob("*.sol"))
    proc = subprocess.run(
        [sys.executable, "-m", "detector.cli", str(dest)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 5
    validate_against_schema(payload)
    assert sorted(item["file"] for item in payload) == names
    for item in payload:
        if item["verdict"] != "MALICIOUS":
            continue
        assert item["evidence"]
        n_lines = len((dest / item["file"]).read_text(encoding="utf-8").splitlines())
        for ev in item["evidence"]:
            assert "line" in ev
            assert 1 <= ev["line"] <= n_lines
    assert proc.stderr.strip()
    p4 = next(item for item in payload if item["file"] == "P4_CappedMint_sol.sol")
    mint_reasons = [row for row in p4["reasons"] if row.startswith(rule_title("BAL_PRIV_MINT"))]
    assert mint_reasons, p4["reasons"]
    assert any("(bounded:" in row for row in mint_reasons), mint_reasons


def test_cli_submission_stdout_stays_json_when_workers_log(tmp_path: Path) -> None:
    dest = _flat_tier0(tmp_path)
    env = {
        **os.environ,
        "PYTHONWARNINGS": "always",
        "DETECTOR_LOG_LEVEL": "DEBUG",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "detector.cli", str(dest)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 5
    validate_against_schema(payload)


def test_run_sh_submission_tier0(tmp_path: Path) -> None:
    dest = _flat_tier0(tmp_path)
    env = {**os.environ, "DETECTOR_NO_DOCKER": "1"}
    proc = subprocess.run(
        ["./run.sh", str(dest)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert len(payload) == 5
    validate_against_schema(payload)


def test_run_submission_degrades_when_scratch_unavailable(
    tmp_path: Path, monkeypatch
) -> None:
    dest = _flat_tier0(tmp_path)

    def _raise_erofs(*_args, **_kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr("detector.compile.tempfile.mkdtemp", _raise_erofs)
    objs = run_submission(dest, timeout_s=120)
    assert len(objs) == 5
    expected = {
        "P1": "BENIGN",
        "P2": "MALICIOUS",
        "P3": "MALICIOUS",
        "P4": "BENIGN",
        "P5": "MALICIOUS",
    }
    got = {}
    for item in objs:
        for prefix in expected:
            if item["file"].startswith(f"{prefix}_"):
                got[prefix] = item["verdict"]
                break
    assert got == expected


def test_docker_entry_mode_uses_output_dir(monkeypatch) -> None:
    monkeypatch.delenv("DETECTOR_MODE", raising=False)
    monkeypatch.setattr(docker_entry.os.path, "isdir", lambda path: path == "/output")
    monkeypatch.setattr(docker_entry.os, "access", lambda path, mode: path == "/output")
    assert docker_entry._mode() == "bench"
    monkeypatch.setattr(docker_entry.os.path, "isdir", lambda path: False)
    assert docker_entry._mode() == "submission"


def test_docker_entry_mode_env_submission_overrides_writable_output(monkeypatch) -> None:
    monkeypatch.setenv("DETECTOR_MODE", "submission")
    monkeypatch.setattr(docker_entry.os.path, "isdir", lambda path: path == "/output")
    monkeypatch.setattr(docker_entry.os, "access", lambda path, mode: path == "/output")
    assert docker_entry._mode() == "submission"


def test_docker_entry_mode_env_bench_overrides_missing_output(monkeypatch) -> None:
    monkeypatch.setenv("DETECTOR_MODE", "bench")
    monkeypatch.setattr(docker_entry.os.path, "isdir", lambda path: False)
    monkeypatch.setattr(docker_entry.os, "access", lambda path, mode: False)
    assert docker_entry._mode() == "bench"


def test_docker_entry_mode_env_garbage_falls_back_to_auto(monkeypatch) -> None:
    monkeypatch.setenv("DETECTOR_MODE", "garbage")
    monkeypatch.setattr(docker_entry.os.path, "isdir", lambda path: path == "/output")
    monkeypatch.setattr(docker_entry.os, "access", lambda path, mode: path == "/output")
    assert docker_entry._mode() == "bench"
    monkeypatch.setattr(docker_entry.os.path, "isdir", lambda path: False)
    assert docker_entry._mode() == "submission"


def test_docker_entry_bench_argv(monkeypatch) -> None:
    seen: list[list[str]] = []
    monkeypatch.setattr(docker_entry, "_mode", lambda: "bench")
    monkeypatch.setattr(
        docker_entry.cli,
        "main",
        lambda argv: seen.append(list(argv)) or 0,
    )
    assert docker_entry.main(["--timeout", "30"]) == 0
    assert seen == [["/input", "/output/results.json", "--timeout", "30"]]


def test_docker_entry_submission_argv(monkeypatch) -> None:
    seen: list[list[str]] = []
    monkeypatch.setattr(docker_entry, "_mode", lambda: "submission")
    monkeypatch.setattr(
        docker_entry.cli,
        "main",
        lambda argv: seen.append(list(argv)) or 0,
    )
    assert docker_entry.main(["--budget", "60"]) == 0
    assert seen == [["/input", "--budget", "60"]]


def _freeze_tree(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            os.chmod(os.path.join(dirpath, name), 0o444)
        for name in dirnames:
            os.chmod(os.path.join(dirpath, name), 0o555)
    os.chmod(root, 0o555)


def _thaw_tree(root: Path) -> None:
    try:
        os.chmod(root, 0o755)
    except OSError:
        pass
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        try:
            os.chmod(dirpath, 0o755)
        except OSError:
            pass
        for name in filenames:
            try:
                os.chmod(os.path.join(dirpath, name), 0o644)
            except OSError:
                pass


def test_cli_submission_read_only_ladder_file(tmp_path: Path) -> None:
    src = tmp_path / "T.sol"
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.19;\n"
        "contract T { mapping(address=>uint) b; address o; "
        "constructor(){o=msg.sender;} "
        "function mint(address a,uint v) external { require(msg.sender==o); b[a]+=v; } "
        "function transfer(address t,uint v) external { b[msg.sender]-=v; b[t]+=v; } }\n",
        encoding="utf-8",
    )
    _freeze_tree(tmp_path)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "detector.cli", str(tmp_path)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        _thaw_tree(tmp_path)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    validate_against_schema(payload)
    assert len(payload) == 1
    assert payload[0]["file"] == "T.sol"
    assert payload[0]["verdict"] == "MALICIOUS"


def test_usdc_exit_addr_gate_carries_governance_note() -> None:
    path = (
        REPO_ROOT / "cases" / "tier3_benign_risky" / "usdc_fiattoken" / "FiatTokenV1.sol"
    )
    result = analyze_file(path, path.name, input_root=path.parent)
    obj = to_judge_object(result, path)
    validate_against_schema([obj])
    assert obj["verdict"] == "MALICIOUS"
    gate = [row for row in obj["reasons"] if row.startswith(rule_title("EXIT_ADDR_GATE"))]
    assert gate, obj["reasons"]
    assert any("(governance:" in row for row in gate), gate
