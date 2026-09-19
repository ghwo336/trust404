from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

from baybench.models import parse_result

REPO = Path(__file__).resolve().parents[1]
TOOL_PY = REPO / "tools" / "baseline_keyword" / "tool.py"

CLEAN_ERC20 = """\
pragma solidity 0.8.20;

contract Token {
    string public name = "Token";
    string public symbol = "TOK";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount);
        require(balanceOf[from] >= amount);
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

MINT_SRC = """\
pragma solidity 0.8.20;
contract Minter {
    function mint(address to, uint256 amount) external {}
}
"""


def _load_tool():
    spec = importlib.util.spec_from_file_location("baseline_keyword_tool", TOOL_PY)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_scan_text_mint_finding() -> None:
    tool = _load_tool()
    findings = tool.scan_text(MINT_SRC)
    assert findings
    assert any(
        f["rule_id"] == "BAL_PRIV_MINT" and f["family"] == "B" and f["severity"] == "HIGH"
        for f in findings
    )


def test_scan_text_clean_erc20_has_no_findings() -> None:
    tool = _load_tool()
    assert tool.scan_text(CLEAN_ERC20) == []


def test_classify_mint_malicious_and_clean_benign(tmp_path: Path) -> None:
    tool = _load_tool()
    mal_dir = tmp_path / "tier1" / "BAL_PRIV_MINT" / "mal"
    mal_dir.mkdir(parents=True)
    (mal_dir / "mal.sol").write_text(MINT_SRC, encoding="utf-8")
    ben_dir = tmp_path / "tier1" / "clean" / "ben"
    ben_dir.mkdir(parents=True)
    (ben_dir / "token.sol").write_text(CLEAN_ERC20, encoding="utf-8")

    by_file = {row["file"]: row for row in tool.classify(tmp_path)}
    mal = by_file["tier1/BAL_PRIV_MINT/mal/mal.sol"]
    ben = by_file["tier1/clean/ben/token.sol"]
    assert mal["verdict"] == "Malicious"
    assert any(f["rule_id"] == "BAL_PRIV_MINT" for f in mal["findings"])
    assert ben["verdict"] == "Benign"
    assert not ben.get("findings")


def test_cli_writes_schema_valid_results(tmp_path: Path) -> None:
    inp = tmp_path / "input"
    mal_dir = inp / "mal"
    ben_dir = inp / "ben"
    mal_dir.mkdir(parents=True)
    ben_dir.mkdir(parents=True)
    (mal_dir / "mal.sol").write_text(MINT_SRC, encoding="utf-8")
    (ben_dir / "token.sol").write_text(CLEAN_ERC20, encoding="utf-8")
    out = tmp_path / "out" / "results.json"
    proc = subprocess.run(
        [sys.executable, str(TOOL_PY), str(inp), str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    parsed = parse_result(out)
    assert parsed.tool_name == "baseline_keyword"
    by_file = {row.file: row for row in parsed.results}
    assert by_file["mal/mal.sol"].verdict == "Malicious"
    assert any(f.rule_id == "BAL_PRIV_MINT" for f in by_file["mal/mal.sol"].findings)
    assert by_file["ben/token.sol"].verdict == "Benign"
