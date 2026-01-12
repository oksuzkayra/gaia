"""Markdown reporter for Gaia."""

from __future__ import annotations

from typing import Set

from gaia.core.model import AttackSurfaceReport, RiskType


def _count_risky_endpoints(report: AttackSurfaceReport) -> int:
    return sum(1 for ep in report.attack_surface.endpoints if any(r != RiskType.info for p in ep.parameters for r in p.risks))


def _unique_param_names(report: AttackSurfaceReport) -> Set[str]:
    names: Set[str] = set()
    for ep in report.attack_surface.endpoints:
        for p in ep.parameters:
            names.add(p.name)
    return names


def to_markdown_report(report: AttackSurfaceReport) -> str:
    """Render a Markdown report with summary, endpoints, and findings."""
    attack_surface = report.attack_surface
    risky_ep_count = _count_risky_endpoints(report)
    unique_params = _unique_param_names(report)
    ai_enabled = "enabled" if report.llm_provider else "disabled"

    lines = [
        f"# Gaia Report for {attack_surface.url}",
        "",
        "## Summary",
        f"- Total endpoints: {len(attack_surface.endpoints)}",
        f"- Endpoints with risk signals: {risky_ep_count}",
        f"- Unique parameters: {len(unique_params)}",
        f"- AI reasoning: {ai_enabled}",
        f"- LLM provider: {report.llm_provider or 'n/a'}",
        f"- LLM model: {report.llm_model or 'n/a'}",
        "",
        "## Endpoints",
    ]

    for endpoint in attack_surface.endpoints:
        param_desc = ", ".join(p.name for p in endpoint.parameters) if endpoint.parameters else "none"
        risk_hints = sorted({risk.value for p in endpoint.parameters for risk in p.risks if risk != RiskType.info})
        risk_text = f" | Risks: {', '.join(risk_hints)}" if risk_hints else ""
        lines.append(
            f"- {endpoint.method or 'GET'} {endpoint.path} [{endpoint.type.value}] "
            f"(params: {param_desc}){risk_text}"
        )

    param_findings = report.ai_parameter_findings or [f for f in attack_surface.findings if f.affected_parameters]
    if param_findings:
        lines.append("")
        lines.append("## Parameter Risk (AI)")
        for finding in param_findings:
            risks = ", ".join(finding.risk_tags) if finding.risk_tags else ", ".join(risk.value for risk in finding.risks)
            related = ", ".join(finding.related_endpoints)
            params = ", ".join(finding.affected_parameters)
            lines.append(f"- {finding.title} (priority: {finding.priority_label or finding.priority}, risks: {risks})")
            if params:
                lines.append(f"  - Parameter(s): {params}")
            if related:
                lines.append(f"  - Endpoints: {related}")
            lines.append(f"  - Reason: {finding.description}")

    js_findings = report.js_findings or {}
    if js_findings:
        lines.append("")
        lines.append("## JS Findings")
        secrets = js_findings.get("secrets", [])
        emails = js_findings.get("emails", [])
        files = js_findings.get("files", [])
        if secrets:
            lines.append("- Secrets:")
            for s in secrets:
                lines.append(f"  - {s.get('type','secret')}: {s.get('value','')} (source: {s.get('source','')})")
        if emails:
            lines.append("- Emails:")
            for e in emails:
                lines.append(f"  - {e}")
        if files:
            lines.append("- Files:")
            for f in files:
                lines.append(f"  - {f}")

    return "\n".join(lines)


# Backwards compatibility for earlier wiring.
render_markdown = to_markdown_report

__all__ = ["to_markdown_report", "render_markdown"]
