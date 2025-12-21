"""High-level Gaia scanning pipeline."""

from __future__ import annotations

import os
import sys
from typing import Optional
from urllib.parse import urlparse

from gaia.collectors.arjun_params import ArjunCollector
from gaia.collectors.base import ScanContext
from gaia.collectors.gau_wayback import GauCollector
from gaia.collectors.linkfinder_js import LinkFinderCollector
from gaia.collectors.live_html_js import LiveHtmlJsCollector
from gaia.collectors.katana_crawler import KatanaCollector
from gaia.core import analysis
from gaia.core.model import AttackSurfaceReport
from gaia.http_snapshot import INCLUDE_RESPONSES, MAX_FETCHES, fetch_response_snapshot
from gaia.llm.analysis import analyze_with_llm, apply_ai_findings_to_endpoints, apply_baseline_risk_hints
from gaia.llm.provider import get_model_name
from gaia.tools import resolve_tool
from gaia.logging_utils import info, warn, error, is_truthy_env
from gaia.output.filters import filter_endpoints
from gaia.diagnostics import Diagnostics
from gaia.llm.analysis import meaningful_endpoints


def _derive_domain(target_url: str | None) -> str | None:
    if not target_url:
        return None
    parsed = urlparse(target_url)
    return parsed.netloc or None


def normalize_urls_with_uro(urls: list[str], enable_uro: bool, diag: Diagnostics) -> list[str]:
    """Normalize/deduplicate URLs via uro if available, else fallback to simple dedupe."""
    import subprocess
    import shutil

    def _dedupe(items: list[str]) -> list[str]:
        seen = set()
        out: list[str] = []
        for u in items:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    if not enable_uro:
        return _dedupe(urls)

    uro_path = shutil.which("uro")
    if not uro_path:
        warn("uro not found; using built-in normalization.")
        diag.add_error("uro")
        return _dedupe(urls)

    cmd = [uro_path]
    input_data = "\n".join(urls) + "\n" if urls else ""
    try:
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)
    except Exception as exc:  # noqa: BLE001
        warn(f"uro invocation failed; using built-in normalization. {exc}")
        diag.add_error("uro")
        return _dedupe(urls)

    if result.returncode != 0:
        first_line = (result.stderr or "").splitlines()
        warn(f"uro exited with errors; using built-in normalization. {first_line[0] if first_line else ''}")
        diag.add_error("uro")
        return _dedupe(urls)

    normalized = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if normalized:
        print(f"[*] [i] Normalized {len(urls)} -> {len(normalized)} URLs (uro)")
        return _dedupe(normalized)
    return _dedupe(urls)


def run_scan(
    url: Optional[str],
    stdin: bool,
    use_ai: bool,
    use_gau: bool,
    use_arjun: bool,
    use_linkfinder: bool,
    max_urls: int,
    use_uro: bool,
    auto_install: bool,
    use_katana: bool = True,
) -> AttackSurfaceReport:
    """Run the Gaia scan pipeline and return an AttackSurfaceReport."""
    diag = Diagnostics(debug=is_truthy_env("GAIA_DEBUG"))
    if os.getenv("GAIA_DISABLE_KATANA", "false").lower() in {"1", "true", "yes"}:
        use_katana = False
    urls: set[str] = set()
    target_url: str | None = url
    domain: str | None = None

    if stdin:
        for line in sys.stdin:
            stripped = line.strip()
            if stripped:
                urls.add(stripped)
        if urls and not target_url:
            target_url = next(iter(urls))

    if url:
        urls.add(url)

    if target_url:
        domain = _derive_domain(target_url)
    elif urls:
        domain = _derive_domain(next(iter(urls)))

    ctx = ScanContext(
        target_url=target_url,
        domain=domain,
        urls=urls,
        params={},
        js_files=set(),
        metadata={},
    )

    collectors = []
    if target_url:
        if use_katana:
            katana_path = resolve_tool("katana")
            if not katana_path:
                print("[!] katana is required but not found. Install or set GAIA_DISABLE_KATANA=true to skip.")
                sys.exit(1)
            collectors.append(KatanaCollector(base_url=target_url, katana_path=katana_path))
        else:
            collectors.append(LiveHtmlJsCollector())
    if use_gau:
        collectors.append(GauCollector(max_urls=max_urls))
    if use_linkfinder:
        collectors.append(LinkFinderCollector())
    if use_arjun:
        collectors.append(ArjunCollector())

    pre_katana_count = len(ctx.urls)
    pre_gau_count = len(ctx.urls)

    for collector in collectors:
        try:
            ctx = collector.run(ctx)
        except Exception as exc:  # noqa: BLE001
            error(f"Collector {collector.__class__.__name__} failed: {exc}")
            if is_truthy_env("GAIA_DEBUG"):
                import traceback

                traceback.print_exc()
            diag.add_error(collector.__class__.__name__)

        # Emit Katana count immediately after katana completes
        if isinstance(collector, KatanaCollector):
            katana_delta = len(ctx.urls) - pre_katana_count if use_katana else 0
            info(f"[i] Katana: collected {katana_delta} URLs")

    info("Stage 3/7: Collecting historical URLs (gau)" if use_gau else "Stage 3/7: Skipping gau")
    # Stage counts for GAU (after Stage 3 execution)
    gau_delta = len(ctx.urls) - pre_gau_count if use_gau else 0
    if use_gau:
        info(f"[i] GAU: collected {gau_delta} URLs")

    info("Stage 4/7: Extracting params (arjun + query parsing)")
    if len(ctx.urls) > max_urls:
        ctx.urls = set(sorted(ctx.urls)[:max_urls])
    # After potential query parsing inside build_attack_surface; count params later

    info("Stage 5/7: Normalizing URLs (uro) + dedupe/cap")
    normalized_urls = normalize_urls_with_uro(list(ctx.urls), enable_uro=use_uro, diag=diag)
    ctx.urls = set(normalized_urls)
    if len(ctx.urls) > max_urls:
        ctx.urls = set(sorted(ctx.urls)[:max_urls])

    info("Stage 6/7: Analysis (static + optional AI)")
    attack_surface = analysis.build_attack_surface(ctx)
    filtered_eps = filter_endpoints(attack_surface.endpoints, show_assets=False, only_params=False)
    apply_baseline_risk_hints(attack_surface, filtered_eps)
    unique_params_count = len({p.name for ep in attack_surface.endpoints for p in ep.parameters})
    info(f"[i] Params: {unique_params_count} unique parameter names")

    # Optionally fetch response snapshots for parameterized endpoints missing them
    if use_ai and INCLUDE_RESPONSES:
        param_endpoints = [ep for ep in attack_surface.endpoints if ep.parameters]
        to_fetch = [
            ep for ep in param_endpoints if not (ep.response_status or ep.response_snippet or ep.response_headers)
        ][:MAX_FETCHES]
        for ep in to_fetch:
            status, headers, snippet = fetch_response_snapshot(ep.path, target_url or ep.path)
            ep.response_status = status
            ep.response_headers = headers
            ep.response_snippet = snippet

    llm_provider = None
    llm_model = None
    report_param_findings = []
    ai_stats: dict | None = None
    parameter_notes: dict | None = {}
    if use_ai:
        model_name = get_model_name()
        if model_name:
            llm_model = model_name
            llm_provider = "litellm"
            try:
                verbose_ai = os.getenv("GAIA_VERBOSE", "false").lower() in {"1", "true", "yes"}
                meaningful_eps = meaningful_endpoints(filtered_eps)
                findings, ai_stats, param_notes = analyze_with_llm(
                    attack_surface, meaningful_eps, verbose=verbose_ai, model_name=model_name
                )
                apply_ai_findings_to_endpoints(attack_surface, findings)
                attack_surface.findings = findings
                report_param_findings = findings
                parameter_notes = param_notes
            except Exception as exc:  # noqa: BLE001
                error(f"[!] LLM analysis failed: {exc}")
                if is_truthy_env("GAIA_DEBUG"):
                    import traceback

                    traceback.print_exc()
        else:
            print("[!] No LLM provider detected, falling back to static mode.")

    report = AttackSurfaceReport(
        attack_surface=attack_surface,
        llm_provider=llm_provider,
        llm_model=llm_model,
        ai_parameter_findings=report_param_findings,
        ai_stats=ai_stats,
        diagnostics={"errors": diag.total_errors, "debug": diag.debug, "stage_errors": diag.stage_errors},
        parameter_notes=parameter_notes if use_ai else {},
    )
    return report
