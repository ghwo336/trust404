"""Shared fixtures for detector tests. Tier 1 cases are the real test corpus (solc 0.8.20 local)."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CASES = REPO_ROOT / "cases"
TIER1 = CASES / "tier1_pairs"
TIER3 = CASES / "tier3_benign_risky"
HARNESS = TIER1 / "_harness"


def tier1_sol(rule_id: str, twin: str) -> Path:
    """Return the single .sol file of cases/tier1_pairs/<rule_id>/<twin> (twin in {'mal','ben'})."""
    files = sorted((TIER1 / rule_id / twin).glob("*.sol"))
    assert len(files) == 1, f"expected exactly one .sol in {rule_id}/{twin}, got {files}"
    return files[0]


@pytest.fixture(scope="session")
def slither_for():
    """Compile a .sol path with the detector's own compile module; cached per path for the session."""
    from detector.compile import compile_file

    cache: dict[Path, object] = {}

    def _get(path: Path):
        path = Path(path).resolve()
        if path not in cache:
            cache[path] = compile_file(path)
        return cache[path]

    return _get
