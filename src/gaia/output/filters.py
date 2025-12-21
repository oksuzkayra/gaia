"""Shared endpoint filtering helpers for console output and AI selection."""

from __future__ import annotations

from typing import Iterable

from gaia.core.model import Endpoint

STATIC_EXTS = (
    ".js",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".pdf",
    ".txt",
    ".xml",
    ".atom",
    ".rss",
    ".mp4",
    ".mp3",
    ".wav",
    ".avi",
    ".mov",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".7z",
    ".rar",
    ".exe",
    ".dmg",
    ".pkg",
)

TRIVIAL_PARAMS = {"v", "ver", "version", "cb", "cache", "cachebust", "cache_bust", "_", "t", "ts", "timestamp", "r"}
STATIC_PATHS = ("/assets/", "/static/", "/vendor/", "/fonts/", "/images/", "/img/", "/css/", "/js/")
SUSPICIOUS_KEEP = (
    ".git",
    ".env",
    ".htaccess",
    ".htpasswd",
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "swagger",
    "openapi",
    "graphql",
    "graphiql",
    "admin",
    "debug",
    "config",
    "backup",
    ".bak",
    ".old",
    ".sql",
    ".log",
    ".yml",
    ".yaml",
    ".json",
    ".ini",
)


def _is_static(path: str, has_params: bool, param_names: set[str], show_assets: bool) -> bool:
    if show_assets:
        return False
    lowered = path.lower()
    non_trivial_params = {p for p in param_names if p.lower() not in TRIVIAL_PARAMS}
    if has_params and non_trivial_params:
        return False
    if not lowered.startswith("/") and not lowered.startswith("http://") and not lowered.startswith("https://"):
        return True
    if any(token in lowered for token in SUSPICIOUS_KEEP):
        if any(lowered.endswith(ext) for ext in STATIC_EXTS) and ("swagger/static" in lowered or "graphiql" in lowered):
            return True
        return False
    if any(lowered.endswith(ext) for ext in STATIC_EXTS):
        return True
    if any(seg in lowered for seg in STATIC_PATHS):
        return True
    if lowered.startswith("./") and not has_params:
        return True
    return False


def _is_valid_path(path: str) -> bool:
    lowered = path.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return True
    if lowered.startswith("/"):
        return True
    return False


def should_display_endpoint(ep: Endpoint, show_assets: bool = False, only_params: bool = False) -> bool:
    """Return True if endpoint should be shown in console/AI views."""
    if only_params and not ep.parameters:
        return False
    if not _is_valid_path(ep.path):
        return False
    param_names = {p.name for p in ep.parameters}
    has_params = bool(param_names)
    if _is_static(ep.path, has_params, param_names, show_assets):
        return False
    return True


def filter_endpoints(endpoints: Iterable[Endpoint], show_assets: bool = False, only_params: bool = False) -> list[Endpoint]:
    """Filter endpoints using shared predicate."""
    return [ep for ep in endpoints if should_display_endpoint(ep, show_assets=show_assets, only_params=only_params)]


__all__ = ["should_display_endpoint", "filter_endpoints", "TRIVIAL_PARAMS"]
