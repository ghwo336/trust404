from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from baybench.catalog import load_catalog


def test_load_catalog_families_and_rules() -> None:
    cat = load_catalog()
    assert cat["families"] == ["A", "B", "C", "D", "E", "F", "G"]
    assert len(cat["rules"]) == 29
    assert cat["rules"]["EXIT_ADDR_GATE"]["family"] == "A"
    assert cat["rules"]["EXIT_ADDR_GATE"]["severity"] == "HIGH"
    assert cat["rules"]["PONZI_SHAPE"]["family"] == "G"


def test_rule_in_unknown_family_raises_value_error(tmp_path: Path) -> None:
    path = tmp_path / "catalog.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "families": ["A", "B", "C", "D", "E", "F", "G"],
                "rules": {"BAD": {"family": "Z", "severity": "HIGH"}},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_catalog(path)
