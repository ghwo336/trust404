from __future__ import annotations

from pathlib import Path

import pytest
import yaml


def _write_labels(case_dir: Path, payload: dict) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "labels.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False),
        encoding="utf-8",
    )


@pytest.fixture
def tmp_cases(tmp_path: Path) -> Path:
    cases = tmp_path / "cases"

    mal_dir = cases / "tier1_pairs" / "EXIT_ADDR_GATE" / "mal"
    _write_labels(
        mal_dir,
        {
            "id": "tier1/EXIT_ADDR_GATE/mal",
            "file": "mal.sol",
            "preferred_verdict": "Malicious",
            "accepted_verdicts": ["Malicious"],
            "expected_families": ["A"],
            "expected_rule_ids": ["EXIT_ADDR_GATE"],
            "expected_functions": ["setBots", "_transfer"],
            "solc": "0.8.20",
        },
    )
    (mal_dir / "mal.sol").write_text(
        "pragma solidity 0.8.20; contract M {}\n",
        encoding="utf-8",
    )

    ben_dir = cases / "tier1_pairs" / "EXIT_ADDR_GATE" / "ben"
    _write_labels(
        ben_dir,
        {
            "id": "tier1/EXIT_ADDR_GATE/ben",
            "file": "ben.sol",
            "preferred_verdict": "Benign",
            "accepted_verdicts": ["Benign"],
            "solc": "0.8.20",
        },
    )
    (ben_dir / "ben.sol").write_text(
        "pragma solidity 0.8.20; contract B {}\n",
        encoding="utf-8",
    )

    usdc_dir = cases / "tier3_benign_risky" / "usdc"
    _write_labels(
        usdc_dir,
        {
            "id": "tier3/usdc",
            "file": "usdc.sol",
            "preferred_verdict": "Benign",
            "accepted_verdicts": ["Benign", "Uncertain"],
            "solc": "0.6.12",
        },
    )
    (usdc_dir / "usdc.sol").write_text(
        "pragma solidity 0.6.12; contract USDC {}\n",
        encoding="utf-8",
    )

    return cases
