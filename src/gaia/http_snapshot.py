"""Utilities to capture and normalize HTTP response snapshots for LLM context."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin

import httpx

TEXTUAL_TYPES = ("text/", "application/json", "application/javascript", "application/xml")
MAX_BODY_CHARS = int(os.getenv("GAIA_LLM_MAX_BODY_CHARS", "4000"))
INCLUDE_RESPONSES = os.getenv("GAIA_LLM_INCLUDE_RESPONSES", "true").lower() not in {"0", "false", "no"}
MAX_FETCHES = int(os.getenv("GAIA_LLM_MAX_RESPONSES", "50"))
ERROR_HINTS = ("error", "exception", "trace", "stack", "warning", "fatal", "undefined", "sql", "syntax")
HEADER_KEEP = {
    "content-type",
    "location",
    "server",
    "set-cookie",
    "www-authenticate",
    "x-powered-by",
    "x-aspnet-version",
    "x-runtime",
    "via",
    "x-cache",
    "cache-control",
}
HEADER_TRIM = 120
HEADER_MAX = 12


def _is_textual(content_type: str | None) -> bool:
    if not content_type:
        return False
    lowered = content_type.lower()
    return lowered.startswith(TEXTUAL_TYPES) or lowered.endswith("+json") or lowered.endswith("+xml")


def filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    filtered: Dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in HEADER_KEEP:
            if len(filtered) >= HEADER_MAX:
                break
            filtered[k] = str(v)[:HEADER_TRIM]
    return filtered


def build_response_snapshot_from_katana(record: Dict[str, Any]) -> Tuple[Optional[int], Optional[Dict[str, str]], Optional[str]]:
    status = record.get("status") or record.get("status_code")
    headers = record.get("headers")
    body = record.get("body")

    filtered_headers: Optional[Dict[str, str]] = None
    snippet: Optional[str] = None

    if isinstance(headers, dict):
        filtered_headers = filter_headers({str(k): str(v) for k, v in headers.items()})

    content_type = None
    if filtered_headers:
        content_type = filtered_headers.get("Content-Type") or filtered_headers.get("content-type")

    if body and isinstance(body, str):
        snippet = sanitize_snippet(body, content_type)

    return status if isinstance(status, int) else None, filtered_headers, snippet


def fetch_response_snapshot(
    endpoint_path: str,
    base_url: str,
    timeout: float = 5.0,
) -> Tuple[Optional[int], Optional[Dict[str, str]], Optional[str]]:
    """Fetch a response snapshot for an endpoint path."""
    url = endpoint_path
    if not endpoint_path.startswith("http://") and not endpoint_path.startswith("https://"):
        url = urljoin(base_url, endpoint_path)

    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
    except Exception:  # noqa: BLE001
        return None, None, None

    filtered_headers = filter_headers(dict(resp.headers))
    content_type = filtered_headers.get("Content-Type") or filtered_headers.get("content-type")

    snippet: Optional[str] = None
    if resp.text:
        snippet = sanitize_snippet(resp.text, content_type, status=resp.status_code)

    return resp.status_code, filtered_headers, snippet


def _looks_binary(text: str) -> bool:
    sample = text[:1000]
    non_printable = sum(1 for ch in sample if ord(ch) < 9 or (13 < ord(ch) < 32))
    return non_printable / max(len(sample), 1) > 0.2


def sanitize_snippet(body: str, content_type: str | None, max_chars: int = MAX_BODY_CHARS, status: int | None = None) -> Optional[str]:
    if not body:
        return None
    if _looks_binary(body):
        return None

    lower_body = body.lower()
    html_like = (content_type and "html" in content_type.lower()) or ("<html" in lower_body or "<script" in lower_body)
    limit = max_chars
    if html_like:
        limit = min(limit, 400)

    # remove data/base64 blobs
    body = re.sub(r"data:[^\\s]{50,}", "", body)
    lines = body.splitlines()
    error_lines = [ln for ln in lines if any(k in ln.lower() for k in ERROR_HINTS)]
    snippet_source = "\n".join(error_lines) if error_lines else " ".join(body.split())
    if status and status < 400 and not error_lines and html_like:
        snippet_source = snippet_source[:200]
    snippet = snippet_source[:limit]
    if len(snippet_source) > limit:
        snippet += "\n...[truncated]"
    return snippet or None
