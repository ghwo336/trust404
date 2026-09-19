from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from baybench.cli import cli
from baybench.models import load_cases
from baybench.validate import solc_binary

NEED_SOLC_0820 = not solc_binary("0.8.20").is_file()


def _write_case(tmp_path: Path, name: str, source: str, *, notes: str | None = None) -> Path:
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
    return cases


@pytest.mark.skipif(NEED_SOLC_0820, reason="solc 0.8.20 not installed")
def test_validate_compiling_case_exits_0(tmp_path: Path) -> None:
    cases = _write_case(
        tmp_path,
        "ok",
        "pragma solidity 0.8.20; contract Tiny {}\n",
    )
    result = CliRunner().invoke(cli, ["validate", "--cases", str(cases)])
    assert result.exit_code == 0, result.output
    assert "1/1 compiled" in result.output


@pytest.mark.skipif(NEED_SOLC_0820, reason="solc 0.8.20 not installed")
def test_validate_broken_case_exits_1(tmp_path: Path) -> None:
    cases = _write_case(
        tmp_path,
        "bad",
        "pragma solidity 0.8.20; contract Tiny { this is not solidity\n",
    )
    result = CliRunner().invoke(cli, ["validate", "--cases", str(cases)])
    assert result.exit_code == 1, result.output
    assert "0/1 compiled" in result.output
    assert "bad:" in result.output


def test_coverage_prints_n_cases_and_missing_pair(tmp_cases: Path) -> None:
    result = CliRunner().invoke(cli, ["coverage", "--cases", str(tmp_cases)])
    assert result.exit_code == 0, result.output
    assert "n_cases" in result.output
    assert "rules_missing_pair" in result.output


def test_ingest_discord_empty(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    cases = tmp_path / "cases"
    cases.mkdir()
    result = CliRunner().invoke(cli, ["ingest-discord", str(src), "--cases", str(cases)])
    assert result.exit_code == 0, result.output
    created_ids = [line.strip() for line in result.output.splitlines() if line.strip()]
    assert created_ids == []
    assert load_cases(cases, tiers=["0"]) == []
    assert list(cases.rglob("labels.yaml")) == []


def test_ingest_discord_creates_case(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "foo.sol").write_text(
        "pragma solidity ^0.8.0; contract Foo {}\n",
        encoding="utf-8",
    )
    (src / "labels.csv").write_text("file,verdict\nfoo.sol,Malicious\n", encoding="utf-8")
    cases = tmp_path / "cases"
    result = CliRunner().invoke(cli, ["ingest-discord", str(src), "--cases", str(cases)])
    assert result.exit_code == 0, result.output
    loaded = load_cases(cases, tiers=["0"])
    assert len(loaded) == 1
    assert loaded[0].preferred_verdict == "Malicious"


def test_ingest_paper_creates_case(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "t.sol").write_text(
        "pragma solidity ^0.8.0; contract T {}\n",
        encoding="utf-8",
    )
    (src / "manifest.csv").write_text("file,category\nt.sol,Hidden Mint\n", encoding="utf-8")
    cases = tmp_path / "cases"
    result = CliRunner().invoke(
        cli, ["ingest-paper", "crpwarner", str(src), "--cases", str(cases)]
    )
    assert result.exit_code == 0, result.output
    loaded = load_cases(cases, tiers=["2"])
    assert len(loaded) == 1
    assert list(loaded[0].expected_families) == ["B"]


def _stub_cli_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[dict]:
    captured: list[dict] = []

    def fake_run(*_args, **kwargs):
        captured.append(kwargs)
        return {"result": object()}

    monkeypatch.setattr("baybench.cli.run", fake_run)
    monkeypatch.setattr(
        "baybench.cli.build_report",
        lambda *_a, **_k: {
            "scoring": {"weighted_score": 0.0, "overall": {"compile_fail_count": 0}},
            "determinism": {"deterministic": True},
        },
    )
    monkeypatch.setattr(
        "baybench.cli.write_report",
        lambda _reports, _rep: (tmp_path / "report.md", tmp_path / "report.json"),
    )
    return captured


def _invoke_run(tmp_path: Path, extra: list[str]) -> object:
    cases = tmp_path / "cases"
    cases.mkdir(exist_ok=True)
    argv = [
        "run",
        "baseline_keyword",
        "--no-docker",
        "--repeat",
        "2",
        "--cases",
        str(cases),
        "--reports",
        str(tmp_path / "reports"),
        *extra,
    ]
    return CliRunner().invoke(cli, argv)


def test_run_help_lists_timeout() -> None:
    result = CliRunner().invoke(cli, ["run", "--help"])
    assert result.exit_code == 0, result.output
    assert "--timeout" in result.output


def test_run_forwards_timeout_to_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _stub_cli_run(monkeypatch, tmp_path)
    result = _invoke_run(tmp_path, ["--timeout", "42"])
    assert result.exit_code == 0, result.output
    assert captured
    assert all(call["timeout"] == 42 for call in captured)


def test_run_default_timeout_is_600(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _stub_cli_run(monkeypatch, tmp_path)
    result = _invoke_run(tmp_path, [])
    assert result.exit_code == 0, result.output
    assert captured
    assert all(call["timeout"] == 600 for call in captured)


def test_run_timeout_zero_rejected() -> None:
    result = CliRunner().invoke(
        cli, ["run", "baseline_keyword", "--timeout", "0", "--no-docker"]
    )
    assert result.exit_code != 0
    assert "--timeout must be >= 1" in result.output
