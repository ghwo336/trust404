"""Compile helpers: solc pick table, retry ladder, harness compile-fail, OZ remap, multi-file targets."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

import detector.compile as compile_mod
from detector.compile import (
    DEFAULT_SOLC,
    INSTALLED_SOLC,
    MAX_SOLC_ATTEMPTS,
    NO_PRAGMA_LADDER,
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
from tests.detector.conftest import HARNESS, REPO_ROOT, TIER3, tier1_sol

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
        ("pragma solidity ^0.8.20;", "0.8.20"),
        ("pragma solidity >=0.6.0 <0.8.0;", "0.6.12"),
        ("pragma solidity 0.4.24;", "0.4.24"),
        ("pragma solidity ^0.4.24;", "0.4.26"),
        ("pragma solidity 0.8.19;", "0.8.19"),
        ("pragma solidity 0.5.16;", "0.5.16"),
        ("pragma solidity ^0.5.0;", "0.5.17"),
        ("pragma solidity 0.6.6;", "0.6.6"),
        ("pragma solidity ^0.6.0;\npragma solidity >=0.6.2;", "0.6.12"),
        ("pragma solidity ^0.7.0;", "0.7.6"),
        ("contract NoPragma {}", "0.8.20"),
        ("pragma solidity 0.5.0;", "0.5.16"),
        ("pragma solidity 0.8.28;", "0.8.28"),
        ("pragma solidity ^0.8.26;", "0.8.37"),
        ("pragma solidity 0.8.37;", "0.8.37"),
        ("pragma solidity 0.8.38;", "0.8.37"),
    ],
)
def test_pick_solc_table(source: str, expected: str) -> None:
    assert pick_solc(source) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # DEFAULT 0.8.20 is outside the range; lowest minor 0.8, highest satisfying patch 0.8.10.
        ("pragma solidity >=0.8.0 <=0.8.10;", "0.8.10"),
        # DEFAULT does not satisfy; lowest minor 0.4, highest satisfying patch 0.4.26.
        ("pragma solidity >=0.4.22 <0.6.0;", "0.4.26"),
        ("pragma solidity >=0.4.22<0.6.0;", "0.4.26"),
        ("pragma solidity <0.5.0;", "0.4.26"),
        # DEFAULT excluded by a lower bound -> highest patch on the 0.8 minor.
        ("pragma solidity >=0.8.21;", "0.8.37"),
        ("pragma solidity >0.8.20;", "0.8.37"),
        ("pragma solidity ~0.8.24;", "0.8.37"),
        # Two-component literals are X-ranges: 0.7 == >=0.7.0 <0.8.0.
        ("pragma solidity 0.7;", "0.7.6"),
        ("pragma solidity ^0.7;", "0.7.6"),
        # Several pragma statements in one (flattened) file must ALL be satisfied.
        ("pragma solidity ^0.4.24;\ncontract A {}\npragma solidity ^0.4.18;", "0.4.26"),
        ("pragma solidity ^0.8.0;\npragma solidity >=0.8.4;", "0.8.20"),
        # `||` alternatives: any group may satisfy; DEFAULT is preferred when it does.
        ("pragma solidity 0.4.24 || ^0.8.0;", "0.8.20"),
        # Lowest minor 0.4; the only satisfying 0.4 pin is 0.4.24 itself.
        ("pragma solidity 0.4.24 || 0.5.17;", "0.4.24"),
        # Unknown minor -> DEFAULT (legacy).
        ("pragma solidity 0.3.6;", "0.8.20"),
        ("pragma solidity ^0.9.0;", "0.8.20"),
    ],
)
def test_pick_solc_constraint_aware(source: str, expected: str) -> None:
    assert pick_solc(source) == expected


def test_pick_solc_calldata_range_regression(tmp_path: Path) -> None:
    source = (
        "pragma solidity ^0.6.0;\n"
        "pragma solidity >=0.6.0 <0.8.0;\n"
        "pragma solidity >=0.6.2;\n"
        "contract C { function f(address[] calldata a) public {} }\n"
    )
    src = tmp_path / "Calldata.sol"
    src.write_text(source, encoding="utf-8")
    assert pick_solc(source) == "0.6.12"
    result = compile_file_ex(src)
    assert result.note is None
    assert result.version == "0.6.12"


def test_every_installed_solc_has_a_binary() -> None:
    """Pins in INSTALLED_SOLC must exist on disk, or pick_solc hands out a version that cannot run."""
    missing = [v for v in INSTALLED_SOLC if not solc_binary(v).exists()]
    assert missing == []


# --- retry ladder -----------------------------------------------------------------------------


def _listing(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def _in_system_temp(path: Path) -> bool:
    return path.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())


def _detector_temp_names() -> set[str]:
    return {
        name
        for name in os.listdir(tempfile.gettempdir())
        if name.startswith("detector-")
    }


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


@contextmanager
def _readonly_tree(root: Path):
    _freeze_tree(root)
    try:
        yield
    finally:
        _thaw_tree(root)


def _mint_uninstalled() -> str:
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.38;\n"
        "contract T { mapping(address=>uint) b; address o; "
        "constructor(){o=msg.sender;} "
        "function mint(address a,uint v) external { require(msg.sender==o); b[a]+=v; } "
        "function transfer(address t,uint v) external { b[msg.sender]-=v; b[t]+=v; } }\n"
    )


def test_ladder_relaxes_exact_pragma_not_installed(tmp_path: Path) -> None:
    src = tmp_path / "A.sol"
    src.write_text("pragma solidity 0.8.38;\n\ncontract A { uint256 x; function f() public { x = 1; } }\n")
    before = _listing(tmp_path)
    result = compile_file_ex(src)
    assert isinstance(result, CompileResult)
    assert result.version == "0.8.37"
    assert result.note is not None
    assert "relaxed" in result.note
    assert "0.8.38" in result.note
    assert "compiled with 0.8.37" in result.note
    assert result.canonical_path == src.resolve()
    assert result.source_path != result.canonical_path
    assert result.source_path.name == src.name
    assert _in_system_temp(result.source_path)
    assert not result.source_path.resolve().is_relative_to(src.resolve().parent)
    assert not is_temp_copy(result.source_path)
    # The engine must select contracts via source_path (Slither filenames point at the mirror).
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
    assert result.source_path != result.canonical_path
    assert not is_temp_copy(result.source_path)
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
        "pragma solidity 0.8.38;\n"
        "contract D1 {}\n"
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract D2 is D1 { uint256 x; function f() public { x = 1; } }\n"
    )
    before = _listing(tmp_path)
    result = compile_file_ex(src)
    assert result.version == "0.8.37"
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
    src.write_text("pragma solidity 0.8.38;\ncontract F { function f() public { undeclared_x = 1; } }\n")
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
    assert seen_targets[0].resolve() == src.resolve()
    assert all(p.name == "H.sol" for p in seen_targets[1:])
    assert all(not p.resolve().is_relative_to(src.resolve().parent) for p in seen_targets[1:])
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


def test_cleanup_temp_copies_removes_mirror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "Token.sol"
    src.write_text("pragma solidity 0.8.20; contract Token {}\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setenv("DETECTOR_SCRATCH_DIR", str(scratch))
    key = hashlib.sha1(str(src.resolve()).encode()).hexdigest()[:16]
    mirror = scratch / key
    (mirror / "root").mkdir(parents=True)
    (mirror / "root" / "Token.sol").write_text("x\n", encoding="utf-8")
    removed = cleanup_temp_copies(src)
    assert not mirror.exists()
    assert any(path.resolve() == mirror.resolve() for path in removed)


def test_ladder_never_writes_read_only_input(tmp_path: Path) -> None:
    src = tmp_path / "T.sol"
    src.write_text(_mint_uninstalled(), encoding="utf-8")
    before = _listing(tmp_path)
    with _readonly_tree(tmp_path):
        result = compile_file_ex(src, input_root=tmp_path)
    assert result.note is not None
    assert "relaxed" in result.note
    assert "0.8.38" in result.note
    assert _in_system_temp(result.source_path)
    assert not result.source_path.resolve().is_relative_to(tmp_path.resolve())
    assert result.canonical_path == src.resolve()
    assert _listing(tmp_path) == before


def test_first_attempt_success_creates_no_mirror() -> None:
    path = tier1_sol("BAL_PRIV_MINT", "mal")
    before = _detector_temp_names()
    result = compile_file_ex(path)
    after = _detector_temp_names()
    assert result.note is None
    assert after - before == set()


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


def test_solc_binary_prefers_env_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "artifacts"
    fake = root / "solc-9.9.9" / "solc-9.9.9"
    fake.parent.mkdir(parents=True)
    fake.write_text("fake\n", encoding="utf-8")
    monkeypatch.setenv(compile_mod.SOLC_ARTIFACTS_ENV, str(root))
    assert compile_mod.solc_binary("9.9.9") == fake


def test_solc_artifact_roots_default_and_default_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(compile_mod.SOLC_ARTIFACTS_ENV, raising=False)
    roots = compile_mod.solc_artifact_roots()
    assert roots[0] == compile_mod.SOLC_SELECT_ARTIFACTS_DIR
    assert compile_mod.solc_binary(DEFAULT_SOLC).is_file()


def test_solc_binary_missing_version_under_first_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(compile_mod.SOLC_ARTIFACTS_ENV, raising=False)
    path = compile_mod.solc_binary("1.2.3")
    assert path == compile_mod.solc_artifact_roots()[0] / "solc-1.2.3" / "solc-1.2.3"
    assert not path.exists()


def _raise_erofs(*_args, **_kwargs):
    raise OSError(30, "Read-only file system")


def test_scratch_session_degrades_when_mkdtemp_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compile_mod.tempfile, "mkdtemp", _raise_erofs)
    monkeypatch.delenv(compile_mod.SCRATCH_ENV, raising=False)
    with compile_mod.scratch_session() as root:
        assert root is None
    assert compile_mod.SCRATCH_ENV not in os.environ


def test_compile_file_ex_relax_reports_no_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compile_mod.tempfile, "mkdtemp", _raise_erofs)
    monkeypatch.delenv(compile_mod.SCRATCH_ENV, raising=False)
    src = tmp_path / "Relax.sol"
    src.write_text("pragma solidity 0.8.38;\ncontract Relax { uint256 public x; }\n")
    with pytest.raises(CompileError) as ei:
        compile_file_ex(src)
    assert "no scratch" in str(ei.value)


def test_compile_file_ex_first_try_ok_without_scratch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compile_mod.tempfile, "mkdtemp", _raise_erofs)
    monkeypatch.delenv(compile_mod.SCRATCH_ENV, raising=False)
    path = REPO_ROOT / "cases" / "tier0_judge" / "P1_StandardToken_sol" / "P1_StandardToken_sol.sol"
    result = compile_file_ex(path)
    assert result.note is None


def test_installed_solc_matches_versions_file() -> None:
    path = Path(compile_mod.__file__).with_name("solc_versions.txt")
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert INSTALLED_SOLC == tuple(lines)
    tuples = [compile_mod._ver_tuple(ver) for ver in INSTALLED_SOLC]
    assert tuples == sorted(tuples)
    assert len(INSTALLED_SOLC) == len(set(INSTALLED_SOLC))
    assert DEFAULT_SOLC in INSTALLED_SOLC
    for ver in NO_PRAGMA_LADDER:
        assert ver in INSTALLED_SOLC
    for patch in range(38):
        assert f"0.8.{patch}" in INSTALLED_SOLC


def test_dockerfile_installs_from_solc_versions_file() -> None:
    text = (REPO_ROOT / "detector" / "Dockerfile").read_text(encoding="utf-8")
    assert "solc_versions.txt" in text
    version_lit = re.compile(r"\d+\.\d+\.\d+")
    for line in text.splitlines():
        if "solc-select install" in line:
            assert version_lit.search(line) is None


def test_compile_file_ex_exact_0819_is_native(tmp_path: Path) -> None:
    src = tmp_path / "A.sol"
    src.write_text("pragma solidity 0.8.19; contract A { uint256 public x; }\n")
    result = compile_file_ex(src)
    assert result.note is None
    assert result.version == "0.8.19"


def test_rank_oz_trees_security_pausable_prefers_v4(tmp_path: Path) -> None:
    v4 = tmp_path / "v4"
    v5 = tmp_path / "v5"
    (v4 / "security").mkdir(parents=True)
    (v4 / "security" / "Pausable.sol").write_text("//\n", encoding="utf-8")
    (v5 / "utils").mkdir(parents=True)
    (v5 / "utils" / "Pausable.sol").write_text("//\n", encoding="utf-8")
    trees = [("v4", v4), ("v5", v5)]
    source = 'import "@openzeppelin/contracts/security/Pausable.sol";\n'
    assert [tag for tag, _ in compile_mod.rank_oz_trees(source, trees)] == ["v4", "v5"]


def test_rank_oz_trees_utils_pausable_prefers_v5(tmp_path: Path) -> None:
    v4 = tmp_path / "v4"
    v5 = tmp_path / "v5"
    (v4 / "security").mkdir(parents=True)
    (v4 / "security" / "Pausable.sol").write_text("//\n", encoding="utf-8")
    (v5 / "utils").mkdir(parents=True)
    (v5 / "utils" / "Pausable.sol").write_text("//\n", encoding="utf-8")
    trees = [("v4", v4), ("v5", v5)]
    source = 'import "@openzeppelin/contracts/utils/Pausable.sol";\n'
    assert [tag for tag, _ in compile_mod.rank_oz_trees(source, trees)] == ["v5", "v4"]


def test_rank_oz_trees_ownable_tie_prefers_v4(tmp_path: Path) -> None:
    v4 = tmp_path / "v4"
    v5 = tmp_path / "v5"
    (v4 / "access").mkdir(parents=True)
    (v5 / "access").mkdir(parents=True)
    (v4 / "access" / "Ownable.sol").write_text("//\n", encoding="utf-8")
    (v5 / "access" / "Ownable.sol").write_text("//\n", encoding="utf-8")
    trees = [("v4", v4), ("v5", v5)]
    source = 'import "@openzeppelin/contracts/access/Ownable.sol";\n'
    assert [tag for tag, _ in compile_mod.rank_oz_trees(source, trees)] == ["v4", "v5"]


def test_rank_oz_trees_no_imports_keeps_declaration_order(tmp_path: Path) -> None:
    v4 = tmp_path / "v4"
    v5 = tmp_path / "v5"
    v4.mkdir()
    v5.mkdir()
    trees = [("v4", v4), ("v5", v5)]
    assert [tag for tag, _ in compile_mod.rank_oz_trees("contract A {}", trees)] == ["v4", "v5"]


def test_compile_file_ex_oz_v5_unbounded_mint() -> None:
    path = HARNESS / "oz_v5_unbounded_mint" / "OzV5UnboundedMint.sol"
    result = compile_file_ex(path)
    assert result.oz_tag == "v5"
    assert result.note is not None
    assert "oz=v5" in result.note


def test_compile_file_ex_oz_v5_pausable() -> None:
    path = HARNESS / "oz_v5_pausable" / "OzV5Pausable.sol"
    result = compile_file_ex(path)
    assert result.oz_tag == "v5"
    assert result.note == "oz=v5"


def test_compile_file_ex_oz_v4_security_pausable() -> None:
    path = HARNESS / "oz_v4_security_pausable" / "OzV4SecurityPausable.sol"
    result = compile_file_ex(path)
    assert result.oz_tag == "v4"
    assert result.note is None


def test_compile_file_ex_oz_import_stays_v4() -> None:
    path = HARNESS / "oz_import" / "TokenOZ.sol"
    result = compile_file_ex(path)
    assert result.oz_tag == "v4"
    assert result.note is None


def test_compile_file_ex_oz_v5_permit_bumps_solc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DETECTOR_OZ_DIR", "")
    src = tmp_path / "Permit.sol"
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        'import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";\n'
        'contract T is ERC20Permit { constructor() ERC20("T", "T") ERC20Permit("T") {} }\n',
        encoding="utf-8",
    )
    result = compile_file_ex(src)
    assert result.version == "0.8.37"
    assert result.note is not None
    assert "compiled with 0.8.37" in result.note


def test_setup_local_sh_mentions_version_and_requirements() -> None:
    text = (REPO_ROOT / "scripts" / "setup_local.sh").read_text(encoding="utf-8")
    assert "solc_versions.txt" in text
    assert "requirements.txt" in text
