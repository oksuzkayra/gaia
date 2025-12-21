"""Collector primitives used across Gaia."""

from __future__ import annotations

from typing import Any, Dict, Protocol, Set

from pydantic import BaseModel, Field


class ScanContext(BaseModel):
    """Shared state passed between collectors."""

    target_url: str | None = None
    domain: str | None = None
    urls: Set[str] = Field(default_factory=set)
    params: Dict[str, Set[str]] = Field(default_factory=dict)
    js_files: Set[str] = Field(default_factory=set)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    response_snapshots: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}


class Collector(Protocol):
    """Collector implementations enrich the scan context."""

    def run(self, ctx: ScanContext) -> ScanContext:
        ...
