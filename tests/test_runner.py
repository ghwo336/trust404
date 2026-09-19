from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from baybench.models import SchemaError, ToolResult, load_cases
from baybench.runner import RunnerError, docker_run_argv, run_tool, stage_tiers


def _write_labels(case_dir: Path, payload: dict) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "labels.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )


def test_stage_tiers_copies_sources_not_labels(tmp_cases: Path, tmp_path: Path) -> None:
    mf_dir = tmp_cases / "tier2_realworld" / "mf"
    _write_labels(
        mf_dir,
        {
            "id": "tier2/mf",
            "file": "Main.sol",
            "preferred_verdict": "Benign",
            "accepted_verdicts": ["Benign"],
        },
    )
    (mf_dir / "Main.sol").write_text("pragma solidity 0.8.20; contract Main {}\n", encoding="utf-8")
    (mf_dir / "Lib.sol").write_text("pragma solidity 0.8.20; library Lib {}\n", encoding="utf-8")

    dest = tmp_path / "staged"
    staged = stage_tiers(tmp_cases, None, dest)
    cases = load_cases(tmp_cases)

    assert set(staged) == {c.staged_file for c in cases}
    assert all(isinstance(c, type(cases[0])) for c in staged.values())
    for case in cases:
        assert (dest / case.id / case.file).is_file()
        assert not (dest / case.id / "labels.yaml").exists()
    assert list(dest.rglob("labels.yaml")) == []
    assert (dest / "tier2/mf" / "Lib.sol").is_file()
    assert (dest / "tier2/mf" / "Main.sol").is_file()


def test_docker_run_argv_network_none_and_absolute(tmp_path: Path) -> None:
    input_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    image = "baybench/probe_network:latest"
    argv = docker_run_argv(image, input_dir, out_dir)
    net_i = argv.index("--network")
    assert argv[net_i : net_i + 2] == ["--network", "none"]
    assert argv[:3] == ["docker", "run", "--rm"]
    assert f"{input_dir.resolve()}:/input:ro" in argv
    assert f"{out_dir.resolve()}:/output" in argv
    assert ":ro" in f"{input_dir.resolve()}:/input:ro"
    assert argv[-1] == image


def test_run_tool_cmd_mode_parses_results(tmp_path: Path) -> None:
    script = tmp_path / "fake_tool.py"
    script.write_text(
        "\n".join(
            [
                "import json, sys",
                "from pathlib import Path",
                "input_dir = sys.argv[1]",
                "results_path = Path(sys.argv[2])",
                "results_path.write_text(",
                "    json.dumps({",
                "        'tool': {'name': 'fake'},",
                "        'results': [{'file': 'a.sol', 'verdict': 'Benign'}],",
                "    }),",
                "    encoding='utf-8',",
                ")",
                "",
            ]
        ),
        encoding="utf-8",
    )
    input_dir = tmp_path / "input"
    out_dir = tmp_path / "output"
    input_dir.mkdir()
    tool_cfg = {
        "name": "fake",
        "cmd": f"{sys.executable} {script} {{input}} {{output}}/results.json",
    }
    res = run_tool(tool_cfg, input_dir, out_dir, use_docker=False)
    assert res["tool"] == "fake"
    assert isinstance(res["result"], ToolResult)
    assert res["result"].tool_name == "fake"
    assert res["result"].results[0].file == "a.sol"
    assert res["result"].results[0].verdict == "Benign"
    assert res["wall_s"] >= 0
    assert res["returncode"] == 0


def test_run_tool_cmd_mode_missing_results_json(tmp_path: Path) -> None:
    script = tmp_path / "noop_tool.py"
    script.write_text("import sys\nsys.stderr.write('no results written')\n", encoding="utf-8")
    input_dir = tmp_path / "input"
    out_dir = tmp_path / "output"
    input_dir.mkdir()
    tool_cfg = {
        "name": "fake",
        "cmd": f"{sys.executable} {script} {{input}} {{output}}/results.json",
    }
    with pytest.raises(RunnerError) as ei:
        run_tool(tool_cfg, input_dir, out_dir, use_docker=False)
    msg = str(ei.value)
    expected = str((out_dir.resolve() / "results.json"))
    assert expected in msg


def test_run_tool_cmd_mode_invalid_json_raises_schema_error(tmp_path: Path) -> None:
    script = tmp_path / "bad_json_tool.py"
    script.write_text(
        "import sys\nfrom pathlib import Path\nPath(sys.argv[2]).write_text('{not json', encoding='utf-8')\n",
        encoding="utf-8",
    )
    input_dir = tmp_path / "input"
    out_dir = tmp_path / "output"
    input_dir.mkdir()
    tool_cfg = {
        "name": "fake",
        "cmd": f"{sys.executable} {script} {{input}} {{output}}/results.json",
    }
    with pytest.raises(SchemaError):
        run_tool(tool_cfg, input_dir, out_dir, use_docker=False)


def test_run_tool_docker_mode_requires_image(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    out_dir = tmp_path / "output"
    input_dir.mkdir()
    with pytest.raises(RunnerError):
        run_tool({"name": "noimg"}, input_dir, out_dir, use_docker=True)
