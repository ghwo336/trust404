"""Compile helpers: solc pick table, harness compile-fail, OZ remap, multi-file targets."""

from __future__ import annotations

from pathlib import Path

import pytest

from detector.compile import (
    INSTALLED_SOLC,
    CompileError,
    compile_file,
    oz_remapping,
    pick_solc,
    solc_binary,
)
from detector.engine import target_contracts
from tests.detector.conftest import HARNESS, TIER3


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("pragma solidity ^0.8.0;", "0.8.20"),
        ("pragma solidity >=0.6.0 <0.8.0;", "0.6.12"),
        ("pragma solidity 0.4.24;", "0.4.26"),
        ("contract NoPragma {}", "0.8.20"),
        ("pragma solidity 0.5.0;", "0.5.17"),
        ("pragma solidity 0.8.28;", "0.8.28"),
        ("pragma solidity ^0.8.26;", "0.8.26"),
        ("pragma solidity 0.8.37;", "0.8.37"),
    ],
)
def test_pick_solc_table(source: str, expected: str) -> None:
    assert pick_solc(source) == expected


def test_every_installed_solc_has_a_binary() -> None:
    """Pins in INSTALLED_SOLC must exist on disk, or pick_solc hands out a version that cannot run."""
    missing = [v for v in INSTALLED_SOLC if not solc_binary(v).exists()]
    assert missing == []


def test_recent_exact_pragma_compiles(tmp_path: Path) -> None:
    src = tmp_path / "Recent.sol"
    src.write_text("pragma solidity 0.8.30;\ncontract Recent { uint256 public x; }\n")
    slither = compile_file(src)
    assert [c.name for c in target_contracts(slither, src)] == ["Recent"]


def test_compile_fail_raises_compile_error() -> None:
    path = HARNESS / "compile_fail" / "broken.sol"
    with pytest.raises(CompileError) as ei:
        compile_file(path)
    message = str(ei.value)
    assert "0.8.20" in message
    assert message  # includes underlying error excerpt


def test_oz_import_compiles_and_targets_token_oz(slither_for) -> None:
    path = HARNESS / "oz_import" / "TokenOZ.sol"
    remap = oz_remapping()
    assert remap is not None
    assert remap.startswith("@openzeppelin/contracts/=")
    slither = slither_for(path)
    names = [c.name for c in target_contracts(slither, path)]
    assert names == ["TokenOZ"]


def test_multi_file_token_excludes_helper_library(slither_for) -> None:
    path = HARNESS / "multi_file" / "Token.sol"
    slither = slither_for(path)
    names = [c.name for c in target_contracts(slither, path)]
    assert names == ["Token"]
    assert "Helper" not in names
    helper_path = HARNESS / "multi_file" / "Helper.sol"
    helper_slither = slither_for(helper_path)
    helper_names = [c.name for c in target_contracts(helper_slither, helper_path)]
    assert helper_names == []


def test_target_contracts_are_leaves_only(slither_for) -> None:
    usdc = TIER3 / "usdc_fiattoken" / "FiatTokenV1.sol"
    assert [c.name for c in target_contracts(slither_for(usdc), usdc)] == ["FiatTokenV1"]
    bancor = TIER3 / "bancor_smarttoken" / "SmartToken.sol"
    assert [c.name for c in target_contracts(slither_for(bancor), bancor)] == ["SmartToken"]
    minime = TIER3 / "lido_ldo_minime" / "MiniMeToken.sol"
    assert [c.name for c in target_contracts(slither_for(minime), minime)] == [
        "MiniMeToken",
        "MiniMeTokenFactory",
    ]
