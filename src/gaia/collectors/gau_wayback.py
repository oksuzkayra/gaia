"""Wayback/GAU collector."""

from __future__ import annotations

from typing import List

from gaia.utils.exec import run_cmd
from .base import Collector, ScanContext


def _record_error(ctx: ScanContext, message: str) -> None:
    errors: List[str] = ctx.metadata.get("errors", [])
    errors.append(message)
    ctx.metadata["errors"] = errors


class GauCollector:
    """Uses gau to gather historical URLs."""

    def __init__(self, max_urls: int = 2000) -> None:
        self.max_urls = max_urls

    def run(self, ctx: ScanContext) -> ScanContext:
        if not ctx.domain:
            return ctx

        result = run_cmd(["gau", ctx.domain])
        if result.returncode != 0:
            _record_error(ctx, f"gau: failed with code {result.returncode}")
            return ctx

        for idx, line in enumerate(result.stdout.splitlines()):
            if idx >= self.max_urls:
                break
            stripped = line.strip()
            if not stripped:
                continue
            ctx.urls.add(stripped)

        return ctx


__all__ = ["GauCollector"]
