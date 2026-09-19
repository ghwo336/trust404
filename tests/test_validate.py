from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from baybench.models import Case, load_cases
from baybench.validate import compile_case, solc_binary

REPO_ROOT = Path(__file__).resolve().parents[1]
NEED_SOLC_0820 = not solc_binary("0.8.20").is_file()


def _write_case(tmp_path: Path, name: str, source: str, *, notes: str | None = None) -> Case:
    cases = tmp_path / "cases"
    case_dir = cases / "tier1_pairs" / name
    case_dir.mkdir(parents=True)
    payload: dict = {
        "id": name,
        "file": f"{name}.sol",
        "preferred_verdict": "Benign",
        "accepted_verdicts": ["Benign"],
        "solc": "0.8.20",
    }
    if notes is not None:
        payload["notes"] = notes
    (case_dir / "labels.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )
    (case_dir / f"{name}.sol").write_text(source, encoding="utf-8")
    return load_cases(cases)[0]


def test_solc_binary_path() -> None:
    path = solc_binary("0.8.20")
    assert str(path).endswith("artifacts/solc-0.8.20/solc-0.8.20")


@pytest.mark.skipif(NEED_SOLC_0820, reason="solc 0.8.20 not installed")
def test_compile_case_valid_contract(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        "ok",
        "pragma solidity 0.8.20; contract Tiny {}\n",
    )
    success, log = compile_case(case, REPO_ROOT)
    assert success is True
    assert isinstance(log, str)


@pytest.mark.skipif(NEED_SOLC_0820, reason="solc 0.8.20 not installed")
def test_compile_case_expected_fail(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        "bad_expected",
        "pragma solidity 0.8.20; contract Tiny { this is not solidity\n",
        notes="expect_compile_fail",
    )
    success, log = compile_case(case, REPO_ROOT)
    assert success is True
    assert isinstance(log, str)


@pytest.mark.skipif(NEED_SOLC_0820, reason="solc 0.8.20 not installed")
def test_compile_case_non_compiling_paper_fixture(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        "paper_broken",
        "pragma solidity 0.8.20; contract Tiny { this is not solidity\n",
        notes="non-compiling paper fixture",
    )
    success, log = compile_case(case, REPO_ROOT)
    assert success is True
    assert "expected_fail" in log


@pytest.mark.skipif(NEED_SOLC_0820, reason="solc 0.8.20 not installed")
def test_compile_case_unexpected_fail(tmp_path: Path) -> None:
    case = _write_case(
        tmp_path,
        "bad",
        "pragma solidity 0.8.20; contract Tiny { this is not solidity\n",
    )
    success, log = compile_case(case, REPO_ROOT)
    assert success is False
    assert isinstance(log, str)
