"""Compile helpers: solc pick table, retry ladder, harness compile-fail, OZ remap, multi-file targets."""

from __future__ import annotations

from pathlib import Path

import pytest

import detector.compile as compile_mod
from detector.compile import (
    DEFAULT_SOLC,
    INSTALLED_SOLC,
    MAX_SOLC_ATTEMPTS,
    TEMP_COPY_SUFFIX,
    CompileError,
    CompileResult,
    cleanup_temp_copies,
    compile_file,
    compile_file_ex,
    is_temp_copy,
    oz_remapping,
    pick_solc,
    solc_binary,
)
from detector.engine import target_contracts
from tests.detector.conftest import HARNESS, REPO_ROOT, TIER3

VENDOR_OZ = REPO_ROOT / "vendor" / "openzeppelin-contracts"
_ERC20_VIA_OZ_PREFIX = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity 0.8.20;\n"
    'import "@oz/token/ERC20/ERC20.sol";\n'
    'contract T is ERC20 { constructor() ERC20("T", "T") {} }\n'
)


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


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # Nothing installed satisfies -> legacy nearest-same-minor of the first literal (0.8.0 -> 0.8.20).
        # The compile then fails with "requires different compiler version" and ladder step (a) rescues it.
        ("pragma solidity >=0.8.0 <=0.8.10;", "0.8.20"),
        # DEFAULT does not satisfy; both 0.4.26 and 0.5.17 do -> LOWEST satisfying (0.4 code breaks on 0.5).
        ("pragma solidity >=0.4.22 <0.6.0;", "0.4.26"),
        ("pragma solidity >=0.4.22<0.6.0;", "0.4.26"),
        ("pragma solidity <0.5.0;", "0.4.26"),
        # DEFAULT excluded by a lower bound -> lowest satisfying above it.
        ("pragma solidity >=0.8.21;", "0.8.24"),
        ("pragma solidity >0.8.20;", "0.8.24"),
        ("pragma solidity ~0.8.24;", "0.8.24"),
        # Two-component literals are X-ranges: 0.7 == >=0.7.0 <0.8.0.
        ("pragma solidity 0.7;", "0.7.6"),
        ("pragma solidity ^0.7;", "0.7.6"),
        # Several pragma statements in one (flattened) file must ALL be satisfied.
        ("pragma solidity ^0.4.24;\ncontract A {}\npragma solidity ^0.4.18;", "0.4.26"),
        ("pragma solidity ^0.8.0;\npragma solidity >=0.8.4;", "0.8.20"),
        # `||` alternatives: any group may satisfy; DEFAULT is preferred when it does.
        ("pragma solidity 0.4.24 || ^0.8.0;", "0.8.20"),
        # 0.4.24 is not installed (exact), 0.5.17 is -> the only satisfying version wins.
        ("pragma solidity 0.4.24 || 0.5.17;", "0.5.17"),
        # Unknown minor -> DEFAULT (legacy).
        ("pragma solidity 0.3.6;", "0.8.20"),
        ("pragma solidity ^0.9.0;", "0.8.20"),
    ],
)
def test_pick_solc_constraint_aware(source: str, expected: str) -> None:
    assert pick_solc(source) == expected


def test_every_installed_solc_has_a_binary() -> None:
    """Pins in INSTALLED_SOLC must exist on disk, or pick_solc hands out a version that cannot run."""
    missing = [v for v in INSTALLED_SOLC if not solc_binary(v).exists()]
    assert missing == []


# --- retry ladder -----------------------------------------------------------------------------


def _listing(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def test_ladder_relaxes_exact_pragma_not_installed(tmp_path: Path) -> None:
    src = tmp_path / "A.sol"
    src.write_text("pragma solidity 0.8.19;\n\ncontract A { uint256 x; function f() public { x = 1; } }\n")
    before = _listing(tmp_path)
    result = compile_file_ex(src)
    assert isinstance(result, CompileResult)
    assert result.version == "0.8.20"
    assert result.note is not None
    assert "relaxed" in result.note
    assert "0.8.19" in result.note
    assert "compiled with 0.8.20" in result.note
    assert result.canonical_path == src.resolve()
    assert result.source_path != result.canonical_path
    assert result.source_path.parent == src.resolve().parent
    assert is_temp_copy(result.source_path)
    # The engine must select contracts via source_path (Slither filenames point at the temp copy).
    contracts = target_contracts(result.slither, result.source_path)
    assert [c.name for c in contracts] == ["A"]
    assert target_contracts(result.slither, result.canonical_path) == []
    # Line numbers are preserved by the relaxation and source text is still readable after cleanup.
    fn = next(f for f in contracts[0].functions_declared if f.name == "f")
    assert fn.source_mapping.lines == [3]
    assert "function f()" in fn.source_mapping.content
    # (v) temp copy removed after success
    assert _listing(tmp_path) == before


def test_ladder_no_pragma_falls_back_to_0_4(tmp_path: Path) -> None:
    src = tmp_path / "B.sol"
    src.write_text("contract B { function f() constant returns (uint) { return 1; } }\n")
    before = _listing(tmp_path)
    result = compile_file_ex(src)
    assert result.version == "0.4.26"
    assert result.note is not None
    assert "no pragma" in result.note
    assert "0.4.26" in result.note
    # No temp copy was needed: the original path is what Slither saw.
    assert result.source_path == result.canonical_path == src.resolve()
    assert [c.name for c in target_contracts(result.slither, src)] == ["B"]
    assert _listing(tmp_path) == before
    # Thin wrapper hands back the same kind of Slither object.
    assert [c.name for c in target_contracts(compile_file(src), src)] == ["B"]


def test_ladder_strips_duplicate_spdx(tmp_path: Path) -> None:
    src = tmp_path / "C.sol"
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.20;\n"
        "contract C1 {}\n"
        "// SPDX-License-Identifier: GPL-3.0\n"
        "contract C2 { uint256 x; function f() public { x = 1; } }\n"
    )
    before = _listing(tmp_path)
    result = compile_file_ex(src)
    assert result.version == "0.8.20"
    assert result.note is not None
    assert "SPDX" in result.note
    assert "compiled with 0.8.20" in result.note
    assert is_temp_copy(result.source_path)
    contracts = target_contracts(result.slither, result.source_path)
    assert [c.name for c in contracts] == ["C1", "C2"]
    fn = next(f for f in contracts[1].functions_declared if f.name == "f")
    assert fn.source_mapping.lines == [5]
    assert _listing(tmp_path) == before


def test_ladder_combines_relax_and_spdx(tmp_path: Path) -> None:
    """Flattened crpwarner shape: exact old pragma + several `^0.8.0` pragmas + several SPDX lines."""
    src = tmp_path / "D.sol"
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.19;\n"
        "contract D1 {}\n"
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract D2 is D1 { uint256 x; function f() public { x = 1; } }\n"
    )
    before = _listing(tmp_path)
    result = compile_file_ex(src)
    assert result.version == "0.8.20"
    assert result.note is not None
    assert "relaxed" in result.note
    assert "SPDX" in result.note
    assert [c.name for c in target_contracts(result.slither, result.source_path)] == ["D2"]
    assert _listing(tmp_path) == before


def test_ladder_does_not_rescue_semantic_errors(tmp_path: Path) -> None:
    src = tmp_path / "E.sol"
    src.write_text("pragma solidity 0.8.20;\ncontract E { function f() public { undeclared_x = 1; } }\n")
    before = _listing(tmp_path)
    with pytest.raises(CompileError) as ei:
        compile_file_ex(src)
    message = str(ei.value)
    assert "Undeclared identifier" in message
    assert "0.8.20" in message
    assert "retry ladder" in message
    # (v) temp copy removed (never created) after failure
    assert _listing(tmp_path) == before


def test_ladder_failure_after_relaxation_cleans_up_and_keeps_original_error(tmp_path: Path) -> None:
    src = tmp_path / "F.sol"
    src.write_text("pragma solidity 0.8.19;\ncontract F { function f() public { undeclared_x = 1; } }\n")
    before = _listing(tmp_path)
    with pytest.raises(CompileError) as ei:
        compile_file_ex(src)
    message = str(ei.value)
    assert "requires different compiler version" in message  # the ORIGINAL first error
    assert "retry ladder" in message
    assert "Undeclared identifier" in message  # the relaxed attempt's error is in the log
    assert _listing(tmp_path) == before


def test_ladder_no_pragma_broken_file_is_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A no-pragma file that fails everywhere gets at most MAX_SOLC_ATTEMPTS Slither constructions."""
    calls: list[tuple[str, str]] = []

    class _AlwaysFails:
        def __init__(self, target: str, **kwargs) -> None:
            calls.append((Path(target).name, Path(kwargs["solc"]).name))
            raise RuntimeError("Error: ParserError: Expected '{' but got 'constant'")

    monkeypatch.setattr(compile_mod, "Slither", _AlwaysFails)
    src = tmp_path / "G.sol"
    src.write_text("contract G { function f() constant returns (uint) { return 1; } }\n")
    with pytest.raises(CompileError) as ei:
        compile_file_ex(src)
    assert len(calls) <= MAX_SOLC_ATTEMPTS
    assert [ver for _, ver in calls] == [
        "solc-0.8.20",
        "solc-0.4.26",
        "solc-0.5.17",
        "solc-0.6.12",
        "solc-0.7.6",
    ]
    assert all(name == "G.sol" for name, _ in calls)
    assert "solc 0.8.20" in str(ei.value)


def test_ladder_relax_then_spdx_is_capped_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every failure claims a new fixable error: the ladder still stops within the cap and removes the copy."""
    calls: list[str] = []
    seen_targets: list[Path] = []

    class _Chameleon:
        def __init__(self, target: str, **kwargs) -> None:
            calls.append(Path(target).name)
            seen_targets.append(Path(target))
            assert Path(target).is_file()  # temp copy exists while Slither runs
            if len(calls) == 1:
                raise RuntimeError("Error: Source file requires different compiler version")
            raise RuntimeError("Error: Multiple SPDX license identifiers found in source file")

    monkeypatch.setattr(compile_mod, "Slither", _Chameleon)
    src = tmp_path / "H.sol"
    src.write_text("pragma solidity 0.8.19;\ncontract H {}\n")
    before = _listing(tmp_path)
    with pytest.raises(CompileError):
        compile_file_ex(src)
    assert len(calls) <= MAX_SOLC_ATTEMPTS
    assert calls[0] == "H.sol"
    assert all(is_temp_copy(p) for p in seen_targets[1:])
    assert _listing(tmp_path) == before


def test_temp_copy_suffix_and_predicate(tmp_path: Path) -> None:
    assert TEMP_COPY_SUFFIX.endswith(".sol")
    assert is_temp_copy(tmp_path / f"Token{TEMP_COPY_SUFFIX}")
    assert not is_temp_copy(tmp_path / "Token.sol")


def test_cleanup_temp_copies_removes_only_the_sibling_copy(tmp_path: Path) -> None:
    src = tmp_path / "Token.sol"
    src.write_text("pragma solidity 0.8.20; contract Token {}\n")
    other = tmp_path / f"Other{TEMP_COPY_SUFFIX}"
    other.write_text("")
    assert cleanup_temp_copies(src) == []
    stray = tmp_path / f"Token{TEMP_COPY_SUFFIX}"
    stray.write_text("")
    assert cleanup_temp_copies(src) == [stray.resolve()]
    assert not stray.exists()
    assert other.exists() and src.exists()


def test_good_files_never_trigger_the_ladder() -> None:
    for path in (
        HARNESS / "oz_import" / "TokenOZ.sol",
        HARNESS / "multi_file" / "Token.sol",
    ):
        result = compile_file_ex(path)
        assert result.note is None
        assert result.version == DEFAULT_SOLC
        assert result.source_path == result.canonical_path == path.resolve()


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


def _link(dest: Path, target: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.symlink_to(target)


def test_remappings_txt_maps_prefix(tmp_path: Path) -> None:
    _link(tmp_path / "lib" / "oz" / "contracts", VENDOR_OZ)
    (tmp_path / "remappings.txt").write_text("@oz/=lib/oz/contracts/\n", encoding="utf-8")
    src = tmp_path / "Token.sol"
    src.write_text(_ERC20_VIA_OZ_PREFIX, encoding="utf-8")
    result = compile_file_ex(src, input_root=tmp_path)
    assert [c.name for c in target_contracts(result.slither, src)] == ["T"]


def test_foundry_toml_profile_remappings(tmp_path: Path) -> None:
    _link(tmp_path / "lib" / "oz" / "contracts", VENDOR_OZ)
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\nremappings = ["@oz/=lib/oz/contracts/"]\n',
        encoding="utf-8",
    )
    src = tmp_path / "Token.sol"
    src.write_text(_ERC20_VIA_OZ_PREFIX, encoding="utf-8")
    result = compile_file_ex(src, input_root=tmp_path)
    assert [c.name for c in target_contracts(result.slither, src)] == ["T"]


def test_nested_relative_import_uses_input_root_allow_paths(tmp_path: Path) -> None:
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "I.sol").write_text(
        "pragma solidity 0.8.20;\ninterface I { function ping() external; }\n",
        encoding="utf-8",
    )
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    src = nested / "C.sol"
    src.write_text(
        "pragma solidity 0.8.20;\n"
        'import "../../shared/I.sol";\n'
        "contract C { uint256 public x; function f(I) public { x = 1; } }\n",
        encoding="utf-8",
    )
    result = compile_file_ex(src, input_root=tmp_path)
    assert [c.name for c in target_contracts(result.slither, src)] == ["C"]


def test_ladder_strips_utf8_bom(tmp_path: Path) -> None:
    src = tmp_path / "Bom.sol"
    src.write_text(
        "\ufeffpragma solidity 0.8.20;\ncontract Bom { uint256 public x; }\n",
        encoding="utf-8",
    )
    before = _listing(tmp_path)
    result = compile_file_ex(src)
    assert isinstance(result, CompileResult)
    assert result.note is not None
    assert "BOM" in result.note
    assert [c.name for c in target_contracts(result.slither, result.source_path)] == ["Bom"]
    leftover = [name for name in _listing(tmp_path) if TEMP_COPY_SUFFIX in name]
    assert leftover == []
    assert _listing(tmp_path) == before
