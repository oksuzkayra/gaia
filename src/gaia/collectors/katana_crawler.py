"""Katana-based crawler collector."""

from __future__ import annotations

import json
from typing import List, Optional
from urllib.parse import urlparse

from gaia.http_snapshot import build_response_snapshot_from_katana
from gaia.utils.exec import run_cmd
from gaia.logging_utils import warn, is_truthy_env
from .base import ScanContext


def _record_error(ctx: ScanContext, message: str) -> None:
    errors: List[str] = ctx.metadata.get("errors", [])
    errors.append(message)
    ctx.metadata["errors"] = errors


class KatanaCollector:
    """Run Katana crawler against a base URL and collect discovered URLs."""

    def __init__(
        self,
        base_url: str,
        katana_path: str,
        *,
        depth: int = 3,
        extra_args: Optional[List[str]] = None,
    ) -> None:
        self.base_url = base_url
        self.katana_path = katana_path
        self.depth = depth
        self.extra_args = extra_args or []

    def run(self, ctx: ScanContext) -> ScanContext:
        verbose = is_truthy_env("GAIA_VERBOSE")
        cmd = [
            self.katana_path,
            "-u",
            self.base_url,
            "-jc",
            "-j",
            "-silent",
            "-nc",
            "-depth",
            str(self.depth),
        ]
        cmd.extend(self.extra_args)

        result = run_cmd(cmd)
        if result.returncode != 0:
            msg = f"Katana failed (exit={result.returncode})."
            if verbose and result.stderr:
                msg += f" stderr: {result.stderr[:500]}"
            warn(msg)
            return ctx

        discovered = 0
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            url = self._extract_url(obj)
            if not url:
                continue
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                continue
            before = len(ctx.urls)
            ctx.urls.add(url)
            if len(ctx.urls) > before:
                discovered += 1
            status, headers, snippet = build_response_snapshot_from_katana(obj)
            if status or headers or snippet:
                ctx.response_snapshots[url] = {
                    "status": status,
                    "headers": headers,
                    "snippet": snippet,
                }

        if discovered == 0:
            msg = "Katana produced no URLs."
            if verbose:
                detail_parts = []
                if result.stderr:
                    detail_parts.append(result.stderr[:300])
                # include a sample stdout line if available
                sample = next((l for l in result.stdout.splitlines() if l.strip()), "")
                if sample:
                    detail_parts.append(sample[:300])
                if detail_parts:
                    msg += " " + " | ".join(detail_parts)
            warn(msg)
        return ctx

    def _extract_url(self, obj: dict) -> str | None:
        from urllib.parse import urljoin

        candidates = [
            obj.get("url"),
            (obj.get("request") or {}).get("url") if isinstance(obj.get("request"), dict) else None,
            (obj.get("request") or {}).get("endpoint") if isinstance(obj.get("request"), dict) else None,
            obj.get("endpoint"),
            obj.get("result"),
            obj.get("raw"),
            obj.get("data"),
        ]
        for cand in candidates:
            if not isinstance(cand, str):
                continue
            cand = cand.strip()
            if not cand:
                continue
            if cand.startswith(("http://", "https://")):
                return cand
            if cand.startswith("/"):
                return urljoin(self.base_url, cand)
        return None


__all__ = ["KatanaCollector"]
