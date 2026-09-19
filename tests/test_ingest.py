from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from baybench.ingest import ingest_discord, ingest_paper, pin_solc
from baybench.models import load_cases
from baybench.validate import solc_binary

NEED_SOLC_0820 = not solc_binary("0.8.20").is_file()

TINY_OK = "pragma solidity ^0.8.0;\ncontract Tiny {}\n"
TINY_BROKEN = "pragma solidity 0.8.20;\ncontract Tiny { this is not solidity\n"


def test_pin_solc_exact_and_ranges() -> None:
    assert pin_solc("0.8.20") == "0.8.20"
    assert pin_solc("^0.8.0") == "0.8.24"
    assert pin_solc("0.4.24") == "0.4.26"
    assert pin_solc("^0.6.0") == "0.6.12"
    assert pin_solc("garbage") == "0.8.20"


def _write_paper_src(src: Path, sol_name: str, category: str, source: str) -> None:
    src.mkdir(parents=True, exist_ok=True)
    (src / sol_name).write_text(source, encoding="utf-8")
    (src / "manifest.csv").write_text(
        f"file,category\n{sol_name},{category}\n",
        encoding="utf-8",
    )


def test_ingest_paper_crpwarner_hidden_mint(tmp_path: Path) -> None:
    src = tmp_path / "src"
    cases_root = tmp_path / "cases"
    _write_paper_src(src, "t.sol", "Hidden Mint", TINY_OK)

    ids = ingest_paper("crpwarner", src, cases_root)
    assert ids == ["tier2/crpwarner/t_sol"]

    loaded = load_cases(cases_root)
    assert len(loaded) == 1
    case = loaded[0]
    assert case.id == "tier2/crpwarner/t_sol"
    assert case.expected_families == ("B",)
    assert case.solc == "0.8.24"
    assert case.preferred_verdict == "Malicious"
    assert case.accepted_verdicts == ("Malicious",)
    labels = yaml.safe_load((case.dir / "labels.yaml").read_text(encoding="utf-8"))
    assert labels["source"] == "crpwarner manifest: Hidden Mint"


def test_ingest_paper_unknown_category(tmp_path: Path) -> None:
    src = tmp_path / "src"
    cases_root = tmp_path / "cases"
    _write_paper_src(src, "t.sol", "NotARealBackdoor", TINY_OK)

    ids = ingest_paper("crpwarner", src, cases_root)
    assert ids == ["tier2/crpwarner/t_sol"]

    case = load_cases(cases_root)[0]
    assert case.expected_families == ()
    assert "unknown category" in case.notes
    assert "NotARealBackdoor" in case.notes
    labels = yaml.safe_load((case.dir / "labels.yaml").read_text(encoding="utf-8"))
    assert "expected_families" not in labels


def test_ingest_paper_bad_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pied-piper|crpwarner|honeybadger"):
        ingest_paper("no-such-paper", tmp_path / "src", tmp_path / "cases")


def test_ingest_paper_missing_manifest(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "t.sol").write_text(TINY_OK, encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="manifest"):
        ingest_paper("crpwarner", src, tmp_path / "cases")


@pytest.mark.skipif(NEED_SOLC_0820, reason="solc 0.8.20 not installed")
def test_ingest_paper_compile_check_broken(tmp_path: Path) -> None:
    src = tmp_path / "src"
    cases_root = tmp_path / "cases"
    _write_paper_src(src, "t.sol", "Hidden Mint", TINY_BROKEN)

    ingest_paper("crpwarner", src, cases_root, compile_check=True)
    case = load_cases(cases_root)[0]
    assert case.preferred_verdict == "Uncertain"
    assert case.accepted_verdicts == ("Uncertain",)
    assert "non-compiling" in case.notes
    assert case.expected_families == ("B",)


def test_ingest_discord_labels_and_scaffold(tmp_path: Path) -> None:
    src = tmp_path / "discord"
    src.mkdir()
    (src / "marked.sol").write_text(TINY_OK, encoding="utf-8")
    (src / "other.sol").write_text(TINY_OK, encoding="utf-8")
    (src / "labels.csv").write_text(
        "file,verdict\nmarked.sol,Malicious\n",
        encoding="utf-8",
    )
    cases_root = tmp_path / "tier0_judge"

    ids = ingest_discord(src, cases_root)
    assert set(ids) == {"tier0/marked_sol", "tier0/other_sol"}

    loaded = {c.id: c for c in load_cases(cases_root)}
    assert set(loaded) == set(ids)

    marked = loaded["tier0/marked_sol"]
    assert marked.preferred_verdict == "Malicious"
    assert marked.accepted_verdicts == ("Malicious",)

    other = loaded["tier0/other_sol"]
    assert other.preferred_verdict == "Uncertain"
    assert set(other.accepted_verdicts) == {"Benign", "Malicious", "Uncertain"}
    assert "TODO: set organizer label" in other.notes
