"""Static analysis utilities for Gaia."""

from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict, Dict, Iterable, List, Set, Tuple
from urllib.parse import parse_qs, urlparse

from gaia.collectors.base import ScanContext
from gaia.core.model import (
    AttackSurface,
    Endpoint,
    EndpointType,
    Parameter,
    RiskType,
    SourceTool,
)
from gaia.http_snapshot import filter_headers


def normalize_param_name(name: str) -> str:
    """Normalize parameter names by stripping query syntax and whitespace."""
    if not name:
        return name
    return name.lstrip(" ?&").strip()


def infer_param_risks(name: str) -> List[RiskType]:
    """Infer basic risk signals from parameter name heuristics."""
    lowered = name.lower()
    risks: List[RiskType] = []

    id_tokens = ("id", "userid", "user_id", "accountid", "orderid", "uid")
    if any(tok in lowered for tok in id_tokens):
        risks.append(RiskType.idor)

    redirect_tokens = ("redirect", "returnurl", "next", "continue")
    if any(tok in lowered for tok in redirect_tokens):
        risks.append(RiskType.open_redirect)

    url_tokens = ("url", "uri", "link", "target", "callback", "webhook", "feed", "imageurl", "avatar")
    if any(tok in lowered for tok in url_tokens):
        risks.append(RiskType.ssrf)
        if RiskType.open_redirect not in risks:
            risks.append(RiskType.open_redirect)

    logic_tokens = ("amount", "price", "total", "balance", "limit", "credit", "role", "admin", "flag")
    if any(tok in lowered for tok in logic_tokens):
        risks.append(RiskType.business_logic)

    if not risks:
        risks.append(RiskType.info)

    return risks


def infer_param_type(name: str) -> str | None:
    """Best-effort parameter type guess."""
    lowered = name.lower()
    if "id" in lowered:
        return "id"
    if any(tok in lowered for tok in ("url", "uri", "link", "target")):
        return "url"
    if any(tok in lowered for tok in ("amount", "price", "total", "balance", "limit", "credit")):
        return "amount"
    if any(tok in lowered for tok in ("role", "admin", "flag")):
        return "role"
    return None


def _classify_endpoint(path: str) -> EndpointType:
    lowered = path.lower()
    asset_exts = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2")
    if lowered.startswith("/api/") or "/api/" in lowered:
        return EndpointType.api
    if any(tok in lowered for tok in ("/admin", "/manage", "/dashboard")):
        return EndpointType.internal
    if any(tok in lowered for tok in ("/debug", "/dev", "/test")):
        return EndpointType.debug
    if any(lowered.endswith(ext) for ext in asset_exts):
        return EndpointType.asset
    return EndpointType.page


def _aggregate_query_params(urls: Iterable[str]) -> Dict[Tuple[str, str], Set[str]]:
    """Collect query parameter names per (host, path) pair."""
    params_by_endpoint: DefaultDict[Tuple[str, str], Set[str]] = defaultdict(set)
    for url in urls:
        parsed = urlparse(url)
        key = (parsed.netloc, parsed.path or "/")
        query_params = parse_qs(parsed.query)
        for param_name in query_params:
            norm = normalize_param_name(param_name)
            if norm:
                params_by_endpoint[key].add(norm)
    return params_by_endpoint


def _merge_arjun_params(params: Dict[str, Set[str]]) -> Dict[Tuple[str, str], Set[str]]:
    """Map arjun-discovered params into endpoint buckets."""
    mapped: DefaultDict[Tuple[str, str], Set[str]] = defaultdict(set)
    for name, url_set in params.items():
        for url in url_set:
            parsed = urlparse(url)
            key = (parsed.netloc, parsed.path or "/")
            norm = normalize_param_name(name)
            if norm:
                mapped[key].add(norm)
    return mapped


def build_attack_surface(ctx: ScanContext) -> AttackSurface:
    """Convert a ScanContext into an AttackSurface with basic static hints."""
    parsed_target = urlparse(ctx.target_url or next(iter(ctx.urls), "http://localhost"))
    base_url = f"{parsed_target.scheme}://{parsed_target.netloc}" if parsed_target.netloc else "http://localhost"
    target_domain = (ctx.domain or parsed_target.netloc or "").lower()

    def _clean_url(raw: str) -> str | None:
        candidate = raw.strip().strip(":")
        if not candidate or " " in candidate or "\n" in candidate:
            return None
        parsed = urlparse(candidate)
        if parsed.scheme in {"http", "https"}:
            if target_domain and parsed.netloc.lower() != target_domain:
                return None
        else:
            if "http://" in candidate or "https://" in candidate:
                return None
        return candidate

    filtered_urls = {u for u in ( _clean_url(u) for u in ctx.urls ) if u}

    query_params = _aggregate_query_params(filtered_urls)
    arjun_params = _merge_arjun_params(ctx.params)

    # Group URLs by (host, path)
    grouped_urls: DefaultDict[Tuple[str, str], Set[str]] = defaultdict(set)
    for url in filtered_urls:
        parsed = urlparse(url)
        key = (parsed.netloc, parsed.path or "/")
        grouped_urls[key].add(url)

    endpoints: List[Endpoint] = []

    for (host, path), urls in sorted(grouped_urls.items()):
        param_names: Set[str] = set()
        param_names.update(query_params.get((host, path), set()))
        param_names.update(arjun_params.get((host, path), set()))

        # Normalize and deduplicate parameter names
        normalized_params = {
            normalize_param_name(p) for p in param_names if normalize_param_name(p)
        }

        parameters = [
            Parameter(
                name=p,
                inferred_type=infer_param_type(p),
                description=None,
                risks=infer_param_risks(p),
            )
            for p in sorted(normalized_params)
        ]

        endpoint_type = _classify_endpoint(path)
        notes = f"Host: {host}" if host else None

        resp_status = None
        resp_headers = None
        resp_snippet = None
        snapshots = ctx.response_snapshots or {}
        for full_url, snap in snapshots.items():
            parsed = urlparse(full_url)
            if (parsed.netloc, parsed.path or "/") == (host, path):
                resp_status = snap.get("status")
                hdrs = snap.get("headers")
                if hdrs:
                    resp_headers = filter_headers({str(k): str(v) for k, v in hdrs.items()})
                resp_snippet = snap.get("snippet")
                break

        endpoints.append(
            Endpoint(
                path=path or "/",
                method=None,
                type=endpoint_type,
                parameters=parameters,
                sources=[SourceTool.other],
                notes=notes,
                response_status=resp_status,
                response_headers=resp_headers,
                response_snippet=resp_snippet,
            )
        )

    return AttackSurface(url=base_url, endpoints=endpoints, findings=[])
