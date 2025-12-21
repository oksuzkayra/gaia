"""Arjun-based parameter discovery collector placeholder."""

from __future__ import annotations

from collections import defaultdict
import re
from typing import DefaultDict, Dict, List, Set
from urllib.parse import urlparse

from gaia.utils.exec import run_cmd
from .base import Collector, ScanContext


def _record_error(ctx: ScanContext, message: str) -> None:
    """Record non-fatal collector errors."""
    errors: List[str] = ctx.metadata.get("errors", [])
    errors.append(message)
    ctx.metadata["errors"] = errors


class ArjunCollector:
    """Uses arjun to discover parameters on selected endpoints."""

    def __init__(self, per_host_limit: int = 30) -> None:
        self.per_host_limit = per_host_limit
        self._param_re = re.compile(r"^[A-Za-z0-9_\-\.]{1,40}$")

    def _pick_urls_for_arjun(self, urls: Set[str]) -> List[str]:
        patterns = ("/api/", "/rest/", "/v1/", "/v2/", "/graphql", "/ajax")
        per_host_count: DefaultDict[str, int] = defaultdict(int)
        selected: List[str] = []

        for url in sorted(urls):
            parsed = urlparse(url)
            if not parsed.scheme.startswith("http"):
                continue
            if not any(pat in parsed.path for pat in patterns):
                continue
            host = parsed.netloc
            if per_host_count[host] >= self.per_host_limit:
                continue
            per_host_count[host] += 1
            selected.append(url)
        return selected

    def run(self, ctx: ScanContext) -> ScanContext:
        from gaia.tools import resolve_tool

        arjun_path = resolve_tool("arjun")

        for url in self._pick_urls_for_arjun(ctx.urls):
            if not arjun_path:
                _record_error(ctx, "arjun: tool not found")
                break

            result = run_cmd([arjun_path, "-u", url])
            if result.returncode != 0:
                _record_error(ctx, f"arjun: failed for {url}")
                continue

            for line in result.stdout.splitlines():
                text = line.strip()
                if not text:
                    continue
                # Handle comma-separated outputs (e.g., "Found parameters: a,b")
                if "," in text:
                    tokens = [tok.strip() for tok in text.split(",")]
                else:
                    tokens = [text]

                for token in tokens:
                    if not token or " " in token or ":" in token or "/" in token or "%" in token or "," in token:
                        continue
                    if not self._param_re.match(token):
                        continue
                    ctx.params.setdefault(token, set()).add(url)

        return ctx


__all__ = ["ArjunCollector"]
