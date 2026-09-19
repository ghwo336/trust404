"""Rule registry. Later phases append callables; import nothing heavy here."""

from __future__ import annotations

RULES: list = []
