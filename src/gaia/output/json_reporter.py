"""JSON reporter for Gaia."""

from __future__ import annotations

from gaia.core.model import AttackSurfaceReport


def to_json_report(report: AttackSurfaceReport) -> str:
    """Serialize the report to a JSON string."""
    return report.model_dump_json(indent=2)


# Backwards compatibility for earlier wiring.
render_json = to_json_report

__all__ = ["to_json_report", "render_json"]
