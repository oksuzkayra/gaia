"""LLM-based reasoning for Gaia attack surface."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Tuple

from gaia.core.model import AttackSurface, Finding, RiskType
from gaia.llm.provider import get_llm_client
from gaia.logging_utils import warn, error, is_truthy_env

_DEBUG_ENABLED = False


SYSTEM_PROMPT = """
You are a security analyst AI. You receive ONE endpoint at a time.
Use only the provided path/method/params (and optional snapshot) to assess parameter-level risk.

Schema (respond with a single JSON object only):
{
  "method": "GET|POST|...",
  "path": "/path",
  "params": ["p1","p2"],
  "priority": "low|medium|high|critical",
  "risk_tags": [
    "auth","bruteforce","rate_limit","user_enum",
    "ssrf","open_redirect",
    "cmdi","rce",
    "lfi","path_traversal","info_disclosure",
    "idor",
    "sqli","xss","injection",
    "csrf",
    "upload",
    "misc"
  ],
  "why": "1-2 sentences grounded in path/params/snapshot only",
  "test_ideas": ["short test idea 1", "short test idea 2"]
}

Non-negotiable tagging hints (must not be missed):
- command|cmd|exec|shell params -> cmdi,rce (>= medium)
- path|file|filename|dir|folder params -> path_traversal,lfi,info_disclosure (>= medium)
- url|uri|redirect|return|next|callback params -> ssrf,open_redirect (>= medium)
- auth-like paths (login|auth|signin|session|token|oauth|callback|reset|verify|otp|2fa|adminlogin) with params username|password|email|otp|code|token -> auth,bruteforce,rate_limit,user_enum (>= medium)
- id|uid|user_id|userid|account|order params -> idor (>= medium)

Rules:
- Do NOT invent params or paths.
- Include obvious tags when obvious patterns exist.
- Prefer higher-confidence, concise findings.
"""


def _normalize_path(path: str) -> str:
    base = path.split("?", 1)[0]
    if len(base) > 1 and base.endswith("/"):
        base = base.rstrip("/")
    return base


def _normalize_param(name: str) -> str:
    return name.strip().lstrip("?&").lower()


def _priority_from_label(label: str) -> int:
    normalized = label.lower()
    if normalized == "critical":
        return 1
    if normalized == "high":
        return 1
    if normalized == "medium":
        return 3
    if normalized == "low":
        return 5
    return 4


def _map_risk_tags_to_risks(tags: List[str]) -> List[RiskType]:
    mapped: List[RiskType] = []
    for tag in tags:
        t = tag.lower()
        if t == "idor":
            mapped.append(RiskType.idor)
        elif t == "ssrf":
            mapped.append(RiskType.ssrf)
        elif t in ("open_redirect", "open-redirect"):
            mapped.append(RiskType.open_redirect)
        elif t == "xss":
            mapped.append(RiskType.xss)
        elif t == "sqli":
            mapped.append(RiskType.sqli)
        elif t == "crlf":
            mapped.append(RiskType.crlf)
        elif t == "ssti":
            mapped.append(RiskType.ssti)
        elif t == "csti":
            mapped.append(RiskType.csti)
        elif t == "lfi":
            mapped.append(RiskType.lfi)
        elif t == "rfi":
            mapped.append(RiskType.rfi)
        elif t == "path_traversal":
            mapped.append(RiskType.path_traversal)
        elif t == "xxe":
            mapped.append(RiskType.xxe)
        elif t == "cmdi":
            mapped.append(RiskType.cmdi)
        elif t == "rce":
            mapped.append(RiskType.rce)
        elif t in ("bfl", "business_logic"):
            mapped.append(RiskType.business_logic)
        elif t in ("misconfig", "misconfiguration"):
            mapped.append(RiskType.misconfiguration)
        elif t == "upload":
            mapped.append(RiskType.upload)
        elif t == "rate_limit":
            mapped.append(RiskType.rate_limit)
        elif t == "csrf":
            mapped.append(RiskType.csrf)
        elif t == "bruteforce":
            mapped.append(RiskType.bruteforce)
        elif t == "user_enum":
            mapped.append(RiskType.user_enum)
        elif t == "jwt":
            mapped.append(RiskType.jwt)
        elif t == "deserialization":
            mapped.append(RiskType.deserialization)
        elif t == "cache_poisoning":
            mapped.append(RiskType.cache_poisoning)
        elif t == "host_header":
            mapped.append(RiskType.host_header)
        elif t == "request_smuggling":
            mapped.append(RiskType.request_smuggling)
        elif t == "injection":
            mapped.append(RiskType.injection)
        elif t == "auth":
            mapped.append(RiskType.auth)
        elif t == "info_disclosure":
            mapped.append(RiskType.info)
        else:
            mapped.append(RiskType.info)
    return mapped or [RiskType.info]


def _truthy_env(name: str) -> bool:
    return os.getenv(name, "false").lower() in {"1", "true", "yes", "on"}


EXCLUDED_PARAMS = {"_", "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"}


def meaningful_endpoints(endpoints: List[Any]) -> List[Any]:
    """Return endpoints that have meaningful (non-tracking) parameters."""
    meaningful: List[Any] = []
    for ep in endpoints:
        params = []
        for p in ep.parameters:
            norm = _normalize_param(p.name)
            if norm and norm not in EXCLUDED_PARAMS:
                params.append(p)
        if params:
            ep.parameters = params  # keep only meaningful params for LLM payload
            meaningful.append(ep)
    return meaningful


def _fallback_test_idea(risk_tags: List[str], param: str) -> str:
    lower_tags = {t.lower() for t in risk_tags}
    if {"ssrf", "open_redirect", "open-redirect"} & lower_tags or any(k in param for k in ("url", "uri", "redir")):
        return "Try external and internal URLs; observe redirects and any server-side fetch behavior."
    if {"path_traversal", "lfi"} & lower_tags or any(k in param for k in ("path", "file", "dir")):
        return "Try traversal sequences (../) and absolute paths; look for file read errors or sensitive content."
    if {"cmdi", "rce"} & lower_tags or "cmd" in param or "command" in param:
        return "Try benign command markers and metacharacters; look for execution errors or timing differences."
    if "idor" in lower_tags or "id" in param:
        return "Try changing identifier values; verify authorization is enforced."
    if {"auth", "bruteforce", "user_enum", "rate_limit"} & lower_tags or any(k in param for k in ("user", "pass", "otp", "token")):
        return "Try invalid credentials repeatedly; compare errors/timing for enumeration; check rate limiting."
    if {"sqli", "injection"} & lower_tags:
        return "Try single-quote and common payload patterns; watch for SQL errors or behavioral changes."
    if "xss" in lower_tags:
        return "Try harmless HTML/JS markers; check reflection/DOM insertion."
    return "Probe with unexpected values; look for errors, access control issues, or unusual responses."


def _aggregate_param_notes(
    param_notes: Dict[str, Dict[str, Any]],
    params: List[str],
    why: str,
    test_ideas: List[str],
    path: str,
    risk_tags: List[str],
    static_risks: List[str],
    priority_label: str,
) -> None:
    risky_tags = [t for t in risk_tags if t and t.lower() != "misc"]
    priority = priority_label.lower()
    static_nonempty = [r for r in static_risks if r]
    is_risky = bool(risky_tags) or priority in {"medium", "high", "critical"} or bool(static_nonempty)
    if not is_risky:
        return

    for p in params:
        key = _normalize_param(p)
        if not key:
            continue
        entry = param_notes.setdefault(key, {"why": "", "test": "", "paths": []})
        if not entry["why"] and why:
            entry["why"] = why.strip()
        if path and len(entry["paths"]) < 3 and path not in entry["paths"]:
            entry["paths"].append(path)
        if not entry["test"]:
            if test_ideas:
                entry["test"] = test_ideas[0]
            else:
                entry["test"] = _fallback_test_idea(risk_tags or static_nonempty, key)


def _baseline_tags_for_param(param: str, path: str) -> List[str]:
    p = param.lower()
    tags: List[str] = []
    if any(k in p for k in ("cmd", "command", "exec", "shell")):
        tags.extend(["cmdi", "rce"])
    if any(k in p for k in ("path", "file", "filename", "dir", "folder")):
        tags.extend(["path_traversal", "lfi", "info_disclosure"])
    if any(k in p for k in ("url", "uri", "redirect", "return", "next", "callback")):
        tags.extend(["ssrf", "open_redirect"])
    if any(k in p for k in ("id", "uid", "user_id", "userid", "account", "order")):
        tags.append("idor")
    if any(k in p for k in ("username", "password", "email", "otp", "code", "token")) or any(
        k in path.lower() for k in ("login", "auth", "signin", "session", "token", "oauth", "callback", "reset", "verify", "otp", "2fa", "adminlogin")
    ):
        tags.extend(["auth", "bruteforce", "rate_limit", "user_enum"])
    return list(dict.fromkeys(tags))


def apply_baseline_risk_hints(attack_surface: AttackSurface, filtered_endpoints: List[Any]) -> None:
    """Apply deterministic risk hints to parameters."""
    for ep in filtered_endpoints:
        path_norm = _normalize_path(ep.path)
        for param in ep.parameters:
            tags = _baseline_tags_for_param(param.name, path_norm)
            for t in tags:
                risk = _map_risk_tags_to_risks([t])[0]
                if risk not in param.risks:
                    param.risks.append(risk)


def _build_endpoint_payload(endpoint: Any) -> Dict[str, Any]:
    response_obj = None
    if endpoint.response_status is not None or endpoint.response_headers or endpoint.response_snippet:
        status = endpoint.response_status
        headers = endpoint.response_headers or {}
        snippet = endpoint.response_snippet or ""

        def _is_textual_snippet(text: str) -> bool:
            return bool(text) and ("\x00" not in text) and any(ch.isalpha() for ch in text)

        if status and 200 <= status < 300:
            ct = None
            for k, v in headers.items():
                if k.lower() == "content-type":
                    ct = v
                    break
            headers = {"content-type": ct} if ct else {}
            snippet = snippet[:200] if _is_textual_snippet(snippet) else ""
        response_obj = {
            "status": status,
            "headers": headers,
            "body_snippet": snippet,
        }
    return {
        "method": endpoint.method or "GET",
        "path": endpoint.path,
        "params": [p.name for p in endpoint.parameters],
        "static_risks": list({r.value for p in endpoint.parameters for r in p.risks}),
        "response": response_obj,
    }


def analyze_with_llm(
    attack_surface: AttackSurface, filtered_endpoints: List[Any], verbose: bool = False, model_name: str | None = None
) -> Tuple[List[Finding], Dict[str, int], Dict[str, Dict[str, str]]]:
    """Call LLM per endpoint and parse findings."""
    global _DEBUG_ENABLED
    client = get_llm_client()
    stats = {"calls": 0, "success": 0, "fail": 0, "debug": _truthy_env("GAIA_LLM_DEBUG")}
    if not client:
        return [], stats, {}

    if stats["debug"] and not _DEBUG_ENABLED:
        try:
            import litellm

            litellm._turn_on_debug()
            _DEBUG_ENABLED = True
        except Exception:
            pass

    findings: List[Finding] = []
    param_notes: Dict[str, Dict[str, Any]] = {}
    fail_streak = 0
    first_fail_logged = False
    # Cap endpoints for LLM
    try:
        cap = int(os.getenv("GAIA_LLM_MAX_ENDPOINTS", "15"))
    except ValueError:
        cap = 15
    orig_total = len(filtered_endpoints)
    if len(filtered_endpoints) > cap:
        filtered_endpoints = filtered_endpoints[:cap]
        if verbose or _truthy_env("GAIA_DEBUG"):
            sys.stdout.write(f"[*] [i] LLM endpoint cap: analyzing {len(filtered_endpoints)}/{orig_total} endpoints\n")
            sys.stdout.flush()

    total = len(filtered_endpoints)
    last_len = 0
    is_tty = sys.stdout.isatty()

    def _render_progress(done: int, success: int, fail: int, final: bool = False) -> None:
        nonlocal last_len
        if total == 0:
            return
        pct = (done / total) * 100
        msg = f"[AI] {done}/{total} ({pct:.1f}%) | ok={success} fail={fail} | remaining={total - done}"
        if is_tty:
            pad = " " * max(0, last_len - len(msg))
            sys.stdout.write("\r" + msg + pad)
            sys.stdout.flush()
            last_len = len(msg)
            if final:
                sys.stdout.write("\n")
                sys.stdout.flush()
        else:
            if final or done % 10 == 0:
                sys.stdout.write(msg + ("\n" if final else "\r"))
                sys.stdout.flush()
    for ep in filtered_endpoints:
        payload = _build_endpoint_payload(ep)
        prompt = SYSTEM_PROMPT + "\nEndpoint:\n" + json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        stats["calls"] += 1
        try:
            content = client(prompt)
        except Exception as exc:  # noqa: BLE001
            stats["fail"] += 1
            fail_streak += 1
            if (not first_fail_logged) or (stats["fail"] % 5 == 0):
                error(
                    f"LLM call failed (model={model_name or os.getenv('GAIA_LLM_MODEL','unknown')}) "
                    f"for {payload.get('m','GET')} {payload.get('p','')}: {exc.__class__.__name__}: {exc}"
                )
                first_fail_logged = True
            if fail_streak >= 3:
                warn("LLM failures reached threshold; skipping remaining endpoints.")
                break
            _render_progress(stats["success"] + stats["fail"], stats["success"], stats["fail"])
            continue

        fail_streak = 0
        if not content:
            stats["fail"] += 1
            _render_progress(stats["success"] + stats["fail"], stats["success"], stats["fail"])
            continue

        def _parse_json(output: str) -> Dict[str, Any] | None:
            text = output.strip()
            if text.startswith("```"):
                text = text.strip("`")
                if text.lower().startswith("json"):
                    text = text[4:]
            if "{" in text and "}" in text:
                text = text[text.find("{") : text.rfind("}") + 1]
            try:
                return json.loads(text)
            except Exception:
                return None

        parsed = _parse_json(content)
        if parsed is None:
            stats["fail"] += 1
            if is_truthy_env("GAIA_DEBUG"):
                import traceback

                traceback.print_exc()
            _render_progress(stats["success"] + stats["fail"], stats["success"], stats["fail"])
            continue

        method = parsed.get("method") or payload.get("method") or "GET"
        path = parsed.get("path") or payload.get("path") or ""
        params = parsed.get("params") or payload.get("params") or []
        risk_tags = [t for t in parsed.get("risk_tags", []) if t]
        priority_label = parsed.get("priority", "medium")
        why = parsed.get("why", "No reasoning provided.")
        stats["success"] += 1
        allowed_params = {_normalize_param(p) for p in (payload.get("params") or []) if p}
        filtered_params = [p for p in params if _normalize_param(p) in allowed_params]
        if allowed_params and not filtered_params:
            filtered_params = list(allowed_params)

        _aggregate_param_notes(
            param_notes,
            filtered_params,
            why,
            parsed.get("test_ideas", []) or [],
            payload.get("path") or "",
            risk_tags,
            payload.get("static_risks", []),
            priority_label,
        )

        findings.append(
            Finding(
                title=f"Endpoint {path}",
                description=why,
                risks=_map_risk_tags_to_risks(risk_tags),
                risk_tags=risk_tags,
                related_endpoints=[_normalize_path(path)],
                affected_parameters=[_normalize_param(p) for p in filtered_params],
                priority=_priority_from_label(priority_label),
                priority_label=priority_label,
            )
        )
        _render_progress(stats["success"] + stats["fail"], stats["success"], stats["fail"])

    _render_progress(stats["success"] + stats["fail"], stats["success"], stats["fail"], final=True)
    if total:
        summary = f"[i] AI: completed {stats['success'] + stats['fail']} calls (success {stats['success']}, fail {stats['fail']})"
        sys.stdout.write(summary + "\n")
        sys.stdout.flush()

    # Finalize param_notes: include seen paths
    final_notes: Dict[str, Dict[str, str]] = {}
    for name, data in param_notes.items():
        why = data.get("why") or ""
        paths = data.get("paths") or []
        if paths:
            suffix = " (seen on: " + ", ".join(paths[:3]) + ")"
            if suffix not in why:
                why = (why + " " + suffix).strip()
        test = data.get("test") or _fallback_test_idea([], name)
        final_notes[name] = {"why": why, "test": test}

    return findings, stats, final_notes


def apply_ai_findings_to_endpoints(attack_surface: AttackSurface, findings: List[Finding]) -> None:
    """Annotate endpoint parameters with AI risk tags."""
    for finding in findings:
        tags = finding.risk_tags or [r.value for r in finding.risks]
        mapped_risks = _map_risk_tags_to_risks(tags)
        target_path = _normalize_path(finding.related_endpoints[0]) if finding.related_endpoints else None
        target_params = {_normalize_param(p) for p in finding.affected_parameters}
        for ep in attack_surface.endpoints:
            if target_path and _normalize_path(ep.path) != target_path:
                continue
            for param in ep.parameters:
                if _normalize_param(param.name) in target_params:
                    existing = set(param.risks)
                    for mr in mapped_risks:
                        if mr not in existing:
                            param.risks.append(mr)
