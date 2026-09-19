"""Engine batch, timeout/error mapping, compile-ladder integration, and results.json schema validation."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import detector.compile as compile_mod
from detector.compile import TEMP_COPY_SUFFIX
from jsonschema.validators import Draft202012Validator

from detector.engine import _file_result_from_worker, _iter_sol_files, analyze_dir, analyze_file
from detector.model import FileResult, Finding, validate_output, write_results
from tests.detector.conftest import HARNESS, REPO_ROOT

VENDOR_OZ = REPO_ROOT / "vendor" / "openzeppelin-contracts"

RELAXABLE_SOURCE = (
    "pragma solidity 0.8.19;\n"
    "contract A { address public owner; "
    "function set(address o) public { require(msg.sender == owner); owner = o; } }\n"
)


def _sleeper(path: str, rel: str, input_root: str | None = None) -> dict:
    time.sleep(30)
    return {"file": rel, "verdict": "Benign", "findings": []}


def _sleeper_leaving_temp_copy(path: str, rel: str, input_root: str | None = None) -> dict:
    """Simulates a worker killed mid-ladder: the temp copy exists when the timeout fires."""
    src = Path(path)
    src.with_name(src.stem + TEMP_COPY_SUFFIX).write_text("pragma solidity >=0.4.0;\n", encoding="utf-8")
    time.sleep(30)
    return {"file": rel, "verdict": "Benign", "findings": []}


def _raiser(path: str, rel: str, input_root: str | None = None) -> dict:
    raise RuntimeError("boom")


def _listing(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def test_analyze_dir_uses_ladder_temp_path_for_targets(tmp_path, caplog) -> None:
    """(a) a relaxed file yields ONE result (no temp-copy result) with findings attributed to `A`;
    (b) the input dir is left with only the original file; the compile note is logged."""
    src = tmp_path / "A.sol"
    src.write_text(RELAXABLE_SOURCE, encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="detector.engine"):
        results, _skipped = analyze_dir(tmp_path)
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
    relaxed, _ = analyze_dir(relaxed_dir)
    plain, _ = analyze_dir(plain_dir)
    assert relaxed[0] == plain[0]


def test_analyze_dir_ignores_stray_temp_copy(tmp_path) -> None:
    """(c) a leftover `<stem>.__relaxed__.sol` in the input dir is neither analysed nor reported."""
    (tmp_path / "X.sol").write_text("pragma solidity 0.8.20; contract X { uint256 x; function f() public { x = 1; } }\n")
    stray = tmp_path / f"X{TEMP_COPY_SUFFIX}"
    stray.write_text("pragma solidity >=0.4.0; contract X {}\n", encoding="utf-8")
    results, _skipped = analyze_dir(tmp_path)
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
    "trading_switch_owner_bypass/TradingSwitchBypass.sol",
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
    results, skipped = analyze_dir(HARNESS)
    assert skipped == 0
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


def test_internal_finding_payload_round_trips_discriminators(tmp_path) -> None:
    finding = Finding(
        rule_id="BAL_PRIV_MINT",
        family="B",
        severity="INFO",
        contract="Token",
        function="mint",
        lines=(10,),
        reasoning="capped mint",
        base_severity="HIGH",
        discriminators=("constant_cap", "managed_role"),
    )
    public = finding.to_json()
    assert "base_severity" not in public
    assert "discriminators" not in public

    payload = FileResult("x.sol", "Benign", findings=(finding,)).to_json(internal=True)
    restored = _file_result_from_worker(payload)
    assert restored.findings[0] == finding

    out = tmp_path / "results.json"
    obj = write_results(out, [FileResult("x.sol", "Benign", findings=(finding,))])
    schema = json.loads(
        (REPO_ROOT / "detector" / "schema" / "result.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(obj)
    dumped = obj["results"][0]["findings"][0]
    assert "base_severity" not in dumped
    assert "discriminators" not in dumped


def _link(dest: Path, target: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.symlink_to(target)


def _sol_count(directory: Path) -> int:
    return len(_iter_sol_files(directory))


def _write_erc20(path: Path, import_line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.20;\n"
        f"{import_line}\n"
        'contract T is ERC20 { constructor() ERC20("T", "T") {} }\n',
        encoding="utf-8",
    )


def test_foundry_layout_relative_lib_import(tmp_path) -> None:
    _link(tmp_path / "lib" / "openzeppelin-contracts" / "contracts", VENDOR_OZ)
    _write_erc20(
        tmp_path / "src" / "Token.sol",
        'import "../lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";',
    )
    results, skipped = analyze_dir(tmp_path)
    assert [r.file for r in results] == ["src/Token.sol"]
    assert results[0].reason != "compile_failed"
    assert skipped == _sol_count(tmp_path / "lib")
    assert skipped > 0


def test_hardhat_layout_node_modules_automap(tmp_path, monkeypatch) -> None:
    _link(tmp_path / "node_modules" / "@openzeppelin" / "contracts", VENDOR_OZ)
    _write_erc20(
        tmp_path / "contracts" / "Token.sol",
        'import "@openzeppelin/contracts/token/ERC20/ERC20.sol";',
    )
    monkeypatch.setattr(compile_mod, "_oz_dir", lambda: None)
    monkeypatch.setenv("DETECTOR_OZ_DIR", "")
    results, skipped = analyze_dir(tmp_path)
    assert [r.file for r in results] == ["contracts/Token.sol"]
    assert results[0].reason != "compile_failed"
    assert skipped == _sol_count(tmp_path / "node_modules")
    assert skipped > 0


def test_lib_exclusion_negatives(tmp_path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "Math.sol").write_text(
        "pragma solidity 0.8.20; library Math { function add(uint a, uint b) public pure returns (uint) { return a + b; } }\n",
        encoding="utf-8",
    )
    (tmp_path / "lib" / "mylib").mkdir()
    (tmp_path / "lib" / "mylib" / "Util.sol").write_text(
        "pragma solidity 0.8.20; library Util { function id(uint x) public pure returns (uint) { return x; } }\n",
        encoding="utf-8",
    )
    (tmp_path / "lib" / "dep" / "src").mkdir(parents=True)
    (tmp_path / "lib" / "dep" / "src" / "X.sol").write_text(
        "pragma solidity 0.8.20; contract X {}\n",
        encoding="utf-8",
    )
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "Y.sol").write_text(
        "pragma solidity 0.8.20; contract Y {}\n",
        encoding="utf-8",
    )
    results, skipped = analyze_dir(tmp_path)
    assert [r.file for r in results] == ["lib/Math.sol", "lib/mylib/Util.sol"]
    assert all(r.reason != "compile_failed" for r in results)
    assert skipped == 2
