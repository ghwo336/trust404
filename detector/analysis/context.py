"""Per-contract analysis context shared by rules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ContractContext:
    slither: Any
    contract: Any
    input_root: Path
