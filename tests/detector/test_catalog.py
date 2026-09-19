"""Catalog and vendored schema stay aligned with baybench (tests may read yaml)."""

from __future__ import annotations

from pathlib import Path

import yaml

from detector.rules.base import CATALOG, FAMILIES
from tests.detector.conftest import REPO_ROOT


def test_catalog_matches_baybench_yaml() -> None:
    data = yaml.safe_load((REPO_ROOT / "baybench" / "catalog.yaml").read_text(encoding="utf-8"))
    expected = {rule_id: (meta["family"], meta["severity"]) for rule_id, meta in data["rules"].items()}
    assert CATALOG == expected
    assert FAMILIES == ("A", "B", "C", "D", "E", "F", "G")
    assert set(FAMILIES) == set(data["families"])


def test_vendored_schema_bytes_equal_baybench() -> None:
    vendored = (REPO_ROOT / "detector" / "schema" / "result.schema.json").read_bytes()
    bench = (REPO_ROOT / "baybench" / "schema" / "result.schema.json").read_bytes()
    assert vendored == bench
