"""Typer-based CLI entrypoint for Gaia."""

from __future__ import annotations

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    # Failing to load .env should not break CLI
    pass

import os
from pathlib import Path
from typing import Optional

import typer

from gaia import __version__
from gaia.logging_utils import info
from gaia.output import ConsoleReporter, render_json, render_markdown
from gaia.pipeline import run_scan
from gaia.tools import ensure_tools_present

app = typer.Typer(
    add_completion=False,
    help="Gaia - recon and attack surface analysis.",
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.callback(invoke_without_command=True)
def cli_root(
    ctx: typer.Context,
    url: Optional[str] = typer.Option(
        None,
        "-u",
        "--url",
        help="Target URL.",
    ),
    stdin: bool = typer.Option(
        False,
        "--stdin",
        help="Read URLs from stdin instead of -u.",
    ),
    ai: bool = typer.Option(
        True,
        "--ai/--no-ai",
        help="Enable or disable AI reasoning.",
        show_default=True,
    ),
    no_gau: bool = typer.Option(False, "--no-gau", help="Disable gau-based historical collection."),
    no_arjun: bool = typer.Option(False, "--no-arjun", help="Disable arjun parameter discovery."),
    no_linkfinder: bool = typer.Option(False, "--no-linkfinder", help="Disable linkfinder JS discovery."),
    no_uro: bool = typer.Option(False, "--no-uro", help="Disable uro URL normalization."),
    max_urls: int = typer.Option(2000, "--max-urls", help="Upper bound of URLs to keep after collection."),
    auto_install: bool = typer.Option(
        False,
        "--auto-install",
        help="Automatically install missing external tools without prompting.",
    ),
    output_format: str = typer.Option(
        "console",
        "-f",
        "--format",
        help="Output format.",
        case_sensitive=False,
        show_default=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "-o",
        "--output",
        help="Output file path. Defaults to stdout. If not provided, console output is used.",
    ),
    show_assets: bool = typer.Option(
        False,
        "--show-assets",
        help="Show static assets in console output.",
    ),
    only_params: bool = typer.Option(
        False,
        "--only-params",
        help="Show only endpoints that have parameters in console output.",
    ),
) -> None:
    """Run Gaia scan."""
    if ctx.invoked_subcommand:
        return

    if not url and not stdin:
        raise typer.BadParameter("Provide --url or --stdin.")

    output_format = output_format.lower()
    if output_format not in {"md", "json", "console"}:
        raise typer.BadParameter("Format must be 'md', 'json', or 'console'.")

    use_katana = os.getenv("GAIA_DISABLE_KATANA", "false").lower() not in {"1", "true", "yes"}
    use_gau = not no_gau
    use_arjun = not no_arjun
    use_linkfinder = not no_linkfinder
    use_uro = not no_uro

    info("Stage 1/7: Resolving tools")
    enabled_tools: list[str] = []
    if use_katana and url:
        enabled_tools.append("katana")
    if use_gau:
        enabled_tools.append("gau")
    if use_arjun:
        enabled_tools.append("arjun")
    if use_linkfinder:
        enabled_tools.append("linkfinder")

    ensure_tools_present(enabled_tools, auto_install=auto_install)
    info(f"Stage 2/7: Crawling target ({'katana' if use_katana else 'fallback fetcher'})")
    report = run_scan(
        url=url,
        stdin=stdin,
        use_ai=ai,
        use_gau=use_gau,
        use_arjun=use_arjun,
        use_linkfinder=use_linkfinder,
        max_urls=max_urls,
        use_uro=use_uro,
        auto_install=auto_install,
        use_katana=use_katana,
    )

    info("Stage 7/7: Rendering report")
    if output_format == "console" and not output:
        # Rich console output
        ConsoleReporter().render(
            report.attack_surface,
            llm_model=report.llm_model,
            ai_parameter_findings=report.ai_parameter_findings,
            show_assets=show_assets,
            only_params=only_params,
            ai_stats=report.ai_stats,
            diagnostics=report.diagnostics,
        )
        if report.parameter_notes:
            ConsoleReporter().render_parameter_notes(report.parameter_notes)
    else:
        rendered = render_markdown(report) if output_format == "md" else render_json(report)
        if output:
            output.write_text(rendered)
            typer.echo(f"[+] Wrote report to {output}")
        else:
            typer.echo(rendered)


@app.command("version")
def version() -> None:
    """Display Gaia version."""
    typer.echo(f"gaia {__version__}")


def main() -> int:
    """CLI entrypoint for console_scripts."""
    app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
