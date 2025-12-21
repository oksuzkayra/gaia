"""Simple diagnostics counter for Gaia pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class Diagnostics:
    stage_errors: Dict[str, int] = field(default_factory=dict)
    debug: bool = False

    def add_error(self, stage: str) -> None:
        self.stage_errors[stage] = self.stage_errors.get(stage, 0) + 1

    @property
    def total_errors(self) -> int:
        return sum(self.stage_errors.values())


__all__ = ["Diagnostics"]
