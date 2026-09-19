from __future__ import annotations

from pathlib import Path

import yaml

CATALOG_PATH = Path(__file__).with_name("catalog.yaml")

_ALLOWED_SEVERITIES = {"HIGH", "MED", "INFO"}


def load_catalog(path: str | Path | None = None) -> dict:
    """Return {'families': [...], 'rules': {rule_id: {'family': str, 'severity': str}}}."""
    catalog_path = CATALOG_PATH if path is None else Path(path)
    data = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    families = list(data["families"])
    family_set = set(families)
    rules: dict[str, dict[str, str]] = {}
    for rule_id, info in data["rules"].items():
        family = info["family"]
        severity = info["severity"]
        if family not in family_set:
            raise ValueError(f"rule {rule_id}: family {family!r} not in families")
        if severity not in _ALLOWED_SEVERITIES:
            raise ValueError(f"rule {rule_id}: severity {severity!r} not in {_ALLOWED_SEVERITIES}")
        rules[rule_id] = {"family": family, "severity": severity}
    return {"families": families, "rules": rules}
