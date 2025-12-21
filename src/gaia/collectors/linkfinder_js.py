"""LinkFinder collector."""

from __future__ import annotations

import subprocess
import sys
import shutil
from typing import List, Set
from urllib.parse import urlparse

from gaia.tools import resolve_linkfinder_cmd
from gaia.utils.exec import run_cmd
from .base import Collector, ScanContext


def _record_error(ctx: ScanContext, message: str) -> None:
    """Record non-fatal collector errors."""
    errors: List[str] = ctx.metadata.get("errors", [])
    errors.append(message)
    ctx.metadata["errors"] = errors


_NOISE_SUBSTRINGS = [
    "invalid input",
    "ssl error",
    "error",
    "use -h for help",
    "options",
    "usage",
    "processing",
    "chunks",
    "analysis",
    "analyzing",
    "v2.",
    "progress",
    "scanner",
    "running",
    "info",
    "warn",
    "debug",
]


class LinkFinderCollector:
    """Runs linkfinder against discovered JS files."""

    def __init__(self, max_js_files: int = 50) -> None:
        self.max_js_files = max_js_files

    def _candidate_js(self, ctx: ScanContext) -> List[str]:
        js_urls: Set[str] = set(ctx.js_files)
        for url in ctx.urls:
            parsed = urlparse(url)
            if parsed.path.endswith(".js"):
                js_urls.add(url)
        return list(js_urls)[: self.max_js_files]

    def run(self, ctx: ScanContext) -> ScanContext:
        for js_url in self._candidate_js(ctx):
            cmd = resolve_linkfinder_cmd()
            if not cmd:
                _record_error(ctx, "linkfinder: tool not available")
                continue
            cmd = cmd + ["-i", js_url, "-o", "cli"]

            result = run_cmd(cmd)
            if result.returncode != 0:
                _record_error(ctx, f"linkfinder: failed for {js_url}")
                continue

            for line in result.stdout.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                lower = stripped.lower()
                if any(noise in lower for noise in _NOISE_SUBSTRINGS):
                    continue
                ctx.urls.add(stripped)

            ctx.js_files.add(js_url)

        return ctx


__all__ = ["LinkFinderCollector"]
