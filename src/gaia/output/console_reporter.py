"""Rich console reporter for Gaia."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from gaia.core.model import AttackSurface, Finding, RiskType
from gaia.output.filters import filter_endpoints


class ConsoleReporter:
    """Render attack surface information to the console using Rich."""

    def __init__(self) -> None:
        self.console = Console()

    def _summarize(
        self,
        attack_surface: AttackSurface,
        llm_model: str | None,
        filtered_count: int,
        ai_stats: dict | None,
        diagnostics: dict | None,
    ) -> None:
        total_endpoints = len(attack_surface.endpoints)
        risky_endpoints = sum(
            1 for ep in attack_surface.endpoints if any(r != RiskType.info for p in ep.parameters for r in p.risks)
        )
        unique_params = {p.name for ep in attack_surface.endpoints for p in ep.parameters}
        ai_status = "enabled" if llm_model else "disabled"
        ai_model = f"(model={llm_model})" if llm_model else "(no LLM model configured)"
        ai_line = ""
        if ai_stats:
            calls = ai_stats.get("calls", 0)
            success = ai_stats.get("success", 0)
            fail = ai_stats.get("fail", 0)
            debug_on = ai_stats.get("debug", False)
            ai_line = f"AI calls: {calls} (success {success}, fail {fail}) | debug={'on' if debug_on else 'off'}"
        diag_line = ""
        if diagnostics:
            diag_line = f"Diagnostics: debug={'on' if diagnostics.get('debug') else 'off'} errors={diagnostics.get('errors',0)}"

        summary = (
            f"[bold]{attack_surface.url}[/bold]\n"
            f"Total endpoints: {total_endpoints}\n"
            f"Filtered endpoints shown: {filtered_count}\n"
            f"Endpoints with risk signals: {risky_endpoints}\n"
            f"Unique parameters: {len(unique_params)}\n"
            f"AI: {ai_status} {ai_model}"
        )
        if ai_line:
            summary += f"\n{ai_line}"
        if diag_line:
            summary += f"\n{diag_line}"
        self.console.print(Panel(summary, title="[bold cyan]Gaia Summary[/bold cyan]", expand=False))

    def _build_ai_map(self, findings: List[Finding]) -> Dict[str, Dict[str, List[Finding]]]:
        """Map endpoint path -> param name -> findings."""
        mapping: Dict[str, Dict[str, List[Finding]]] = defaultdict(lambda: defaultdict(list))
        for f in findings:
            for ep in f.related_endpoints:
                for param in f.affected_parameters:
                    mapping[ep][param].append(f)
        return mapping

    def render(
        self,
        attack_surface: AttackSurface,
        llm_model: str | None = None,
        ai_parameter_findings: List[Finding] | None = None,
        show_assets: bool = False,
        only_params: bool = False,
        ai_stats: dict | None = None,
        diagnostics: dict | None = None,
    ) -> None:
        ai_findings = ai_parameter_findings or []
        ai_map = self._build_ai_map(ai_findings)

        table = Table(
            title="[bold cyan]Endpoints[/bold cyan]",
            box=box.SIMPLE,
            expand=True,
        )
        table.add_column("Method", style="bold cyan", no_wrap=True)
        table.add_column("Path", style="bold white")
        table.add_column("Params", style="white")
        table.add_column("Risks", style="yellow")

        filtered_eps = filter_endpoints(attack_surface.endpoints, show_assets=show_assets, only_params=only_params)

        self._summarize(attack_surface, llm_model, len(filtered_eps), ai_stats, diagnostics)

        for ep in filtered_eps:
            param_names = {p.name for p in ep.parameters}
            params_set = sorted(param_names)
            params = ", ".join(params_set) if params_set else "[dim]<none>[/dim]"
            static_risks = sorted({r.value for p in ep.parameters for r in p.risks if r != RiskType.info})
            static_risks_str = ", ".join(static_risks) if static_risks else ""

            ai_annotations: List[str] = []
            for pname in {p.name for p in ep.parameters}:
                findings = ai_map.get(ep.path, {}).get(pname, [])
                if not findings:
                    continue
                tags = []
                for f in findings:
                    tag_str = ",".join(f.risk_tags) if f.risk_tags else ",".join(r.value for r in f.risks)
                    priority = f"({f.priority_label or f.priority})"
                    tags.append(f"{tag_str}{priority}")
                ai_annotations.append(f"{pname}→{'|'.join(tags)}")
            ai_str = "[magenta]" + "; ".join(ai_annotations) + "[/magenta]" if ai_annotations else ""
            if static_risks_str and ai_str:
                risks_str = f"{static_risks_str}, {ai_str}"
            elif static_risks_str:
                risks_str = static_risks_str
            elif ai_str:
                risks_str = ai_str
            else:
                risks_str = "[dim]<none>[/dim]"

            table.add_row(
                ep.method or "GET",
                ep.path,
                params,
                risks_str,
            )

        self.console.print(table)

    def render_parameter_notes(self, param_notes: Dict[str, Dict[str, str]]) -> None:
        if not param_notes:
            return
        from rich.text import Text
        from rich.panel import Panel
        from rich.padding import Padding

        self.console.print("[bold underline]Parameter notes[/bold underline]")
        for name, data in sorted(param_notes.items()):
            why = (data.get("why") or "").strip()
            test = (data.get("test") or "").strip()
            tags = data.get("tags") or []

            header = Text("▶ ", style="cyan") + Text(name, style="bold cyan")
            if tags:
                header.append("  ")
                header.append(", ".join(tags), style="dim yellow")

            body_lines: list[Text] = []
            if why:
                body_lines.append(Text("Why:", style="dim italic"))
                body_lines.append(Padding(Text(why), (0, 0, 0, 2)))
            if test:
                body_lines.append(Text("Test idea:", style="yellow"))
                body_lines.append(Padding(Text(test), (0, 0, 0, 2)))

            # Compose and render
            self.console.print(header)
            for line in body_lines:
                self.console.print(line)
            self.console.print("")  # blank line between params

    def render_js_findings(self, js_findings: Dict[str, object]) -> None:
        if not js_findings:
            return
        secrets = js_findings.get("secrets", []) or []
        emails = js_findings.get("emails", []) or []
        files = js_findings.get("files", []) or []

        self.console.print("[bold underline]JS findings[/bold underline]")
        if secrets:
            self.console.print("[bold]Secrets[/bold]")
            for s in secrets[:20]:
                self.console.print(f"- {s.get('type','secret')}: {s.get('value','')} (source: {s.get('source','')})")
            if len(secrets) > 20:
                self.console.print(f"... and {len(secrets) - 20} more")
        if emails:
            self.console.print("[bold]Emails[/bold]")
            for e in list(emails)[:20]:
                self.console.print(f"- {e}")
        if files:
            self.console.print("[bold]Files[/bold]")
            for f in list(files)[:20]:
                self.console.print(f"- {f}")


__all__ = ["ConsoleReporter"]
