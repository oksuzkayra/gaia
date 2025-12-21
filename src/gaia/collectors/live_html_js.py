"""Live HTML/JS collector placeholder."""

from __future__ import annotations

from typing import Iterable, List
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from gaia.config import load_config
from .base import Collector, ScanContext


def _record_error(ctx: ScanContext, message: str) -> None:
    """Record non-fatal collector errors."""
    errors: List[str] = ctx.metadata.get("errors", [])
    errors.append(message)
    ctx.metadata["errors"] = errors


class LiveHtmlJsCollector:
    """Fetches a target URL and extracts HTML/JS artifacts."""

    def __init__(self, timeout: float | None = None) -> None:
        self.timeout = timeout

    def _is_allowed_domain(self, url: str, domain: str | None) -> bool:
        """Check if URL matches target domain constraint."""
        if not domain:
            return True
        parsed = urlparse(url)
        return parsed.netloc.endswith(domain)

    def _extract_urls(self, soup: BeautifulSoup, base_url: str) -> Iterable[str]:
        """Yield candidate URLs from common HTML elements."""
        selectors = [
            ("a", "href"),
            ("form", "action"),
            ("link", "href"),
            ("img", "src"),
            ("script", "src"),
        ]
        for tag, attr in selectors:
            for element in soup.find_all(tag):
                raw = element.get(attr)
                if not raw:
                    continue
                yield urljoin(base_url, raw)

    def run(self, ctx: ScanContext) -> ScanContext:
        if not ctx.target_url:
            return ctx

        config = load_config()
        timeout = self.timeout or config.request_timeout

        try:
            resp = httpx.get(
                ctx.target_url,
                timeout=timeout,
                headers={"User-Agent": config.user_agent},
                follow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            _record_error(ctx, f"live_html_js: fetch error: {exc}")
            return ctx

        ctx.metadata["live_status_code"] = resp.status_code
        soup = BeautifulSoup(resp.text, "html.parser")

        for found_url in self._extract_urls(soup, ctx.target_url):
            parsed = urlparse(found_url)
            if parsed.scheme not in {"http", "https"}:
                continue
            if not self._is_allowed_domain(found_url, ctx.domain):
                continue
            ctx.urls.add(found_url)
            if parsed.path.endswith(".js"):
                ctx.js_files.add(found_url)

        return ctx


__all__ = ["LiveHtmlJsCollector"]
