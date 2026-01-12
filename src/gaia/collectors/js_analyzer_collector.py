"""JS analyzer collector that fetches JS and extracts endpoints/urls/secrets."""

from __future__ import annotations

import os
from typing import List, Set
from urllib.parse import urljoin, urlparse

import httpx

from gaia.analyzers.js_analyzer import analyze_js
from gaia.collectors.base import Collector, ScanContext
from gaia.config import load_config
from gaia.logging_utils import info, warn, is_truthy_env


def _is_binaryish(text: str) -> bool:
    if not text:
        return True
    sample = text[:1000]
    non_printable = sum(1 for ch in sample if ord(ch) < 9 or (13 < ord(ch) < 32))
    return non_printable / max(len(sample), 1) > 0.2


class JsAnalyzerCollector(Collector):
    """Fetch JS files and extract endpoints, URLs, secrets, emails, and files."""

    def __init__(self, max_fetches: int = 25, max_chars: int = 1_000_000) -> None:
        self.max_fetches = max_fetches
        self.max_chars = max_chars

    def _candidate_js(self, ctx: ScanContext) -> List[str]:
        js_urls: Set[str] = set(ctx.js_files)
        for url in ctx.urls:
            if urlparse(url).path.endswith(".js"):
                js_urls.add(url)
        # include snapshots with js content-type
        for url, snap in ctx.response_snapshots.items():
            headers = snap.get("headers") or {}
            ctype = headers.get("Content-Type") or headers.get("content-type") or ""
            if "javascript" in ctype.lower():
                js_urls.add(url)
        return list(js_urls)[: self.max_fetches]

    def run(self, ctx: ScanContext) -> ScanContext:
        if os.getenv("GAIA_DISABLE_JS_ANALYZER", "false").lower() in {"1", "true", "yes"}:
            return ctx

        base_url = ctx.target_url or (next(iter(ctx.urls), "") if ctx.urls else "")
        if not base_url:
            return ctx

        config = load_config()
        headers = {"User-Agent": config.user_agent}
        js_urls = self._candidate_js(ctx)

        total_new_endpoints = 0
        total_new_urls = 0
        secrets: List[dict] = []
        emails: Set[str] = set()
        files: Set[str] = set()

        for js_url in js_urls:
            # Resolve relative URLs to absolute
            if not js_url.startswith(("http://", "https://")):
                js_url = urljoin(base_url, js_url)
            try:
                resp = httpx.get(js_url, timeout=config.request_timeout, headers=headers, follow_redirects=True)
            except Exception as exc:  # noqa: BLE001
                warn(f"JS fetch failed: {js_url} ({exc})")
                continue
            if resp.status_code >= 400:
                continue
            text = resp.text[: self.max_chars]
            if _is_binaryish(text):
                continue
            result = analyze_js(text, js_url, base_url)

            for ep in result["endpoints"]:
                full = urljoin(base_url, ep)
                before = len(ctx.urls)
                ctx.urls.add(full)
                if len(ctx.urls) > before:
                    total_new_endpoints += 1

            for u in result["urls"]:
                before = len(ctx.urls)
                ctx.urls.add(u)
                if len(ctx.urls) > before:
                    total_new_urls += 1

            secrets.extend(result["secrets"])
            emails.update(result["emails"])
            files.update(result["files"])

        js_findings = {
            "secrets": secrets,
            "emails": sorted(emails),
            "files": sorted(files),
            "counts": {
                "secrets": len(secrets),
                "emails": len(emails),
                "files": len(files),
                "endpoints": total_new_endpoints,
                "urls": total_new_urls,
            },
        }
        ctx.metadata["js_findings"] = js_findings
        info(
            f"[i] JS: scanned {len(js_urls)} files, +{total_new_endpoints} new endpoints, +{total_new_urls} new URLs, "
            f"secrets={len(secrets)}, emails={len(emails)}, files={len(files)}"
        )
        return ctx


__all__ = ["JsAnalyzerCollector"]
