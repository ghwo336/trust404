"""Engine batch, timeout/error mapping, compile-ladder integration, and results.json schema validation."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from detector.compile import TEMP_COPY_SUFFIX
from detector.engine import analyze_dir, analyze_file
from detector.model import FileResult, Finding, validate_output, write_results
from tests.detector.conftest import HARNESS, REPO_ROOT

RELAXABLE_SOURCE = (
    "pragma solidity 0.8.19;\n"
    "contract A { address public owner; "
    "function set(address o) public { require(msg.sender == owner); owner = o; } }\n"
)


def _sleeper(path: str, rel: str) -> dict:
    time.sleep(30)
    return {"file": rel, "verdict": "Benign", "findings": []}


def _sleeper_leaving_temp_copy(path: str, rel: str) -> dict:
    """Simulates a worker killed mid-ladder: the temp copy exists when the timeout fires."""
    src = Path(path)
    src.with_name(src.stem + TEMP_COPY_SUFFIX).write_text("pragma solidity >=0.4.0;\n", encoding="utf-8")
    time.sleep(30)
    return {"file": rel, "verdict": "Benign", "findings": []}


def _raiser(path: str, rel: str) -> dict:
    raise RuntimeError("boom")


def _listing(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def test_analyze_dir_uses_ladder_temp_path_for_targets(tmp_path, caplog) -> None:
    """(a) a relaxed file yields ONE result (no temp-copy result) with findings attributed to `A`;
    (b) the input dir is left with only the original file; the compile note is logged."""
    src = tmp_path / "A.sol"
    src.write_text(RELAXABLE_SOURCE, encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="detector.engine"):
        results = analyze_dir(tmp_path)
    assert [r.file for r in results] == ["A.sol"]
    result = results[0]
    assert (result.verdict, result.reason) != ("Uncertain", "compile_failed")
    assert result.reason not in ("compile_failed", "analysis_error", "timeout")
    assert any(f.contract == "A" for f in result.findings)
    assert _listing(tmp_path) == ["A.sol"]
    assert any("relaxed" in rec.getMessage() and "A.sol" in rec.getMessage() for rec in caplog.records)


def test_relaxed_file_matches_plain_compile(tmp_path) -> None:
    """The ladder must not change analysis semantics: 0.8.19-pinned and 0.8.20-pinned twins agree."""
    relaxed_dir = tmp_path / "relaxed"
    plain_dir = tmp_path / "plain"
    relaxed_dir.mkdir()
    plain_dir.mkdir()
    (relaxed_dir / "A.sol").write_text(RELAXABLE_SOURCE, encoding="utf-8")
    (plain_dir / "A.sol").write_text(
        RELAXABLE_SOURCE.replace("pragma solidity 0.8.19;", "pragma solidity 0.8.20;"), encoding="utf-8"
    )
    relaxed = analyze_dir(relaxed_dir)[0]
    plain = analyze_dir(plain_dir)[0]
    assert relaxed == plain


def test_analyze_dir_ignores_stray_temp_copy(tmp_path) -> None:
    """(c) a leftover `<stem>.__relaxed__.sol` in the input dir is neither analysed nor reported."""
    (tmp_path / "X.sol").write_text("pragma solidity 0.8.20; contract X { uint256 x; function f() public { x = 1; } }\n")
    stray = tmp_path / f"X{TEMP_COPY_SUFFIX}"
    stray.write_text("pragma solidity >=0.4.0; contract X {}\n", encoding="utf-8")
    results = analyze_dir(tmp_path)
    assert [r.file for r in results] == ["X.sol"]
    assert results[0].verdict != "Uncertain"
    assert stray.exists()  # skipped, not touched (cleanup only follows a timeout for that file)


def test_timeout_removes_leftover_temp_copy(monkeypatch, tmp_path) -> None:
    src = tmp_path / "T.sol"
    src.write_text("pragma solidity 0.8.19; contract T {}\n", encoding="utf-8")
    monkeypatch.setattr("detector.engine._analyze_in_process", _sleeper_leaving_temp_copy)
    timed = analyze_file(src, "T.sol", timeout_s=2)
    assert timed == FileResult("T.sol", "Uncertain", reason="timeout")
    assert _listing(tmp_path) == ["T.sol"]


HARNESS_FILES = [
    "compile_fail/broken.sol",
    "multi_file/Helper.sol",
    "multi_file/Token.sol",
    "oz_accesscontrol_blacklist/OzRoleBlacklist.sol",
    "oz_import/TokenOZ.sol",
    "oz_ownable2step_token/OzTwoStepToken.sol",
    "oz_ownable_fee_capped/OzFeeCapped.sol",
    "oz_ownable_rug/OzOwnableRug.sol",
    "timelock_self_call/MiniTimelock.sol",
]

# OZ-shaped regression fixtures: verdicts are pinned by their labels.yaml and scored by BAYBENCH,
# not asserted here (known-open detector work). The engine must still compile and analyse them.
OZ_REGRESSION_FILES = (
    "oz_accesscontrol_blacklist/OzRoleBlacklist.sol",
    "oz_ownable2step_token/OzTwoStepToken.sol",
    "oz_ownable_fee_capped/OzFeeCapped.sol",
    "oz_ownable_rug/OzOwnableRug.sol",
    "timelock_self_call/MiniTimelock.sol",
)


def test_analyze_dir_harness() -> None:
    results = analyze_dir(HARNESS)
    files = [r.file for r in results]
    assert files == sorted(files)
    assert files == HARNESS_FILES
    assert files == sorted(p.relative_to(HARNESS).as_posix() for p in HARNESS.rglob("*.sol"))
    by_file = {r.file: r for r in results}
    broken = by_file["compile_fail/broken.sol"]
    assert broken.verdict == "Uncertain"
    assert broken.reason == "compile_failed"
    for rel in ("multi_file/Helper.sol", "multi_file/Token.sol", "oz_import/TokenOZ.sol"):
        assert by_file[rel].verdict == "Benign"
        assert by_file[rel].reason == ""
        assert by_file[rel].findings == ()
    for rel in OZ_REGRESSION_FILES:
        assert by_file[rel].verdict in {"Malicious", "Uncertain", "Benign"}
        assert by_file[rel].reason != "compile_failed"


def test_timeout_and_analysis_error(monkeypatch, tmp_path) -> None:
    dummy = tmp_path / "x.sol"
    dummy.write_text("pragma solidity 0.8.20; contract X {}\n", encoding="utf-8")
    monkeypatch.setattr("detector.engine._analyze_in_process", _sleeper)
    timed = analyze_file(dummy, "x.sol", timeout_s=1)
    assert timed == FileResult("x.sol", "Uncertain", reason="timeout")

    monkeypatch.setattr("detector.engine._analyze_in_process", _raiser)
    failed = analyze_file(dummy, "x.sol", timeout_s=10)
    assert failed == FileResult("x.sol", "Uncertain", reason="analysis_error")


def test_write_results_validates_and_round_trips(tmp_path) -> None:
    results = [
        FileResult(
            file="b.sol",
            verdict="Benign",
        ),
        FileResult(
            file="a.sol",
            verdict="Malicious",
            findings=(
                Finding(
                    rule_id="EXIT_ADDR_GATE",
                    family="A",
                    severity="HIGH",
                    contract="Token",
                    function="transfer",
                    lines=(10, 12),
                    reasoning="addr gate",
                ),
            ),
        ),
    ]
    out = tmp_path / "results.json"
    obj = write_results(out, results)
    validate_output(obj)
    raw = out.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    loaded = json.loads(raw)
    validate_output(loaded)
    assert loaded["tool"]["name"] == "detector"
    assert loaded["results"][0]["file"] == "a.sol"
    assert "reason" not in loaded["results"][0]
    finding = loaded["results"][0]["findings"][0]
    assert set(finding) <= {
        "rule_id",
        "family",
        "severity",
        "contract",
        "function",
        "lines",
        "reasoning",
    }
    vendored = (REPO_ROOT / "detector" / "schema" / "result.schema.json").read_bytes()
    bench = (REPO_ROOT / "baybench" / "schema" / "result.schema.json").read_bytes()
    assert vendored == bench
