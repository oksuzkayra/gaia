"""External tool validation, resolution, and installation helpers."""

from __future__ import annotations

import json
import os
import shutil
import sys
import importlib.util
from pathlib import Path
from typing import Callable, Iterable, List

from gaia.installer import install_arjun, install_gau, install_katana, install_linkfinder
from gaia.logging_utils import info, success, warn

INSTALLERS: dict[str, Callable[[], bool]] = {
    "gau": install_gau,
    "arjun": install_arjun,
    "linkfinder": install_linkfinder,
    "katana": install_katana,
}


def _prompt_install(missing: List[str]) -> bool:
    """Prompt the user to auto-install missing tools."""
    print("[!] Missing required tools:", ", ".join(missing))
    for tool in missing:
        print(f"    - {tool} is required for Gaia to run this feature.")
    choice = input("Auto-install missing tools? (Y/n): ").strip().lower()
    return choice in ("", "y", "yes")


def _attempt_install(tool: str) -> bool:
    installer = INSTALLERS.get(tool)
    if not installer:
        print(f"[!] No installer available for {tool}. Please install manually.")
        return False
    return installer()


def _linkfinder_available() -> bool:
    """Check if LinkFinder is available via binary or importable module."""
    return resolve_linkfinder_cmd() is not None


def _state_dir() -> Path:
    env_dir = os.getenv("GAIA_STATE_DIR")
    if env_dir:
        return Path(env_dir).expanduser()
    return Path.home() / ".gaia"


def get_tools_dir() -> Path:
    """Return Gaia tools directory, creating it if needed."""
    base = _state_dir() / "tools"
    base.mkdir(parents=True, exist_ok=True)
    return base


def resolve_tool(tool_name: str, silent: bool = False) -> str | None:
    """Resolve a tool path from Gaia tools dir or PATH."""
    tools_dir = get_tools_dir()
    candidates = [
        tools_dir / tool_name,
        tools_dir / f"{tool_name}.exe",
    ]
    for cand in candidates:
        if cand.exists():
            return str(cand)

    path_hit = shutil.which(tool_name)
    if path_hit:
        return path_hit

    home = Path.home()
    fallback_candidates = [
        home / "go" / "bin" / tool_name,
        home / ".local" / "bin" / tool_name,
    ]
    for cand in fallback_candidates:
        if cand.exists():
            return str(cand)

    return None


def resolve_linkfinder_cmd() -> list[str] | None:
    """Resolve linkfinder as a binary command list or python -m linkfinder fallback."""
    # Prefer venv/local binary first
    bin_path = resolve_tool("linkfinder", silent=True)
    if bin_path:
        return [bin_path]

    # Check venv/scripts directly
    venv_bin = Path(sys.executable).parent / "linkfinder"
    if venv_bin.exists():
        return [str(venv_bin)]

    # Fallback to module execution if available
    if importlib.util.find_spec("linkfinder") is not None:
        return [sys.executable, "-m", "linkfinder"]

    return None


def ensure_tools_present(enabled_tools: Iterable[str], auto_install: bool = False) -> None:
    """Ensure required external binaries are available, optionally installing them into Gaia tools dir."""
    state_path = _state_dir() / "state.json"
    try:
        old_state = json.loads(state_path.read_text())
    except Exception:
        old_state = {}

    missing: List[str] = []
    for tool in enabled_tools:
        if tool == "linkfinder":
            if not _linkfinder_available():
                missing.append(tool)
        else:
            if resolve_tool(tool) is None:
                missing.append(tool)

    if not missing:
        return

    should_install = auto_install or _prompt_install(missing)
    if not should_install:
        sys.exit(1)

    for tool in missing:
        ok = _attempt_install(tool)
        if not ok:
            print(f"[!] Installation failed or {tool} still missing. Exiting.")
            sys.exit(1)

    # Final check with fresh resolution
    remaining: List[str] = []
    resolved_after: List[str] = []
    for tool in enabled_tools:
        if tool == "linkfinder":
            if _linkfinder_available():
                resolved_after.append(tool)
            else:
                remaining.append(tool)
        else:
            if resolve_tool(tool, silent=True):
                resolved_after.append(tool)
            else:
                remaining.append(tool)

    if remaining:
        print(f"[!] Some tools are still missing after auto-install attempt: {', '.join(remaining)}")
        print("    Please add them to your PATH or install manually, then re-run Gaia.")
        sys.exit(1)
    else:
        # Persist state and only print when changed and installed now
        new_state = dict(old_state)
        for tool in resolved_after:
            path = resolve_tool(tool, silent=True) if tool != "linkfinder" else "module" if resolve_linkfinder_cmd() else None
            if path:
                if old_state.get(tool) != path and tool in missing:
                    success(f"- Installed {tool}")
                new_state[tool] = path
        try:
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps(new_state))
        except Exception:
            pass


__all__ = ["ensure_tools_present", "get_tools_dir", "resolve_tool", "resolve_linkfinder_cmd"]
