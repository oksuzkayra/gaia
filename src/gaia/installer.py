"""Auto-install helpers for external tools used by Gaia."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Optional

from pathlib import Path


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a command and capture output."""
    return subprocess.run(cmd, capture_output=True, text=True)


def _copy_to_tools_dir(src: Path, name: str) -> None:
    """Copy binary to Gaia tools directory."""
    from gaia.tools import get_tools_dir

    tools_dir = get_tools_dir()
    dest = tools_dir / name
    try:
        shutil.copy(src, dest)
    except Exception:  # noqa: BLE001
        print(f"[!] Failed to copy {src} to {dest}")


def install_gau() -> bool:
    """Attempt to install gau using Go."""
    from gaia.tools import get_tools_dir, resolve_tool

    existing = resolve_tool("gau")
    if existing:
        return True

    if shutil.which("go") is None:
        print("[!] Go compiler not found. Install Go or use --no-gau flag.")
        return False

    print("[+] Installing gau via Go...")
    result = _run(["go", "install", "github.com/lc/gau/v2/cmd/gau@latest"])
    if result.returncode != 0:
        print(f"[!] Failed to install gau: {result.stderr.strip()}")
        return False

    go_path = _go_bin_path()
    if go_path:
        gau_bin = Path(go_path) / "gau"
        if gau_bin.exists():
            _copy_to_tools_dir(gau_bin, "gau")
            return True
    # Final attempt: check if copied binary exists
    tools_dir = get_tools_dir()
    if (tools_dir / "gau").exists():
        return True
    return False


def _go_bin_path() -> Optional[str]:
    """Return Go bin path if available."""
    result = _run(["go", "env", "GOPATH"])
    if result.returncode != 0:
        return None
    gopath = result.stdout.strip()
    if not gopath:
        return None
    return os.path.join(gopath, "bin")


def install_arjun() -> bool:
    """Attempt to install arjun using pip."""
    from gaia.tools import resolve_tool

    if resolve_tool("arjun"):
        return True

    print("[+] Installing arjun via pip...")
    result = _run([sys.executable, "-m", "pip", "install", "arjun"])
    if result.returncode != 0:
        print(f"[!] Failed to install arjun: {result.stderr.strip()}")
        return False

    return shutil.which("arjun") is not None


def install_linkfinder() -> bool:
    """Attempt to install LinkFinder using pip (git+ URL)."""
    from gaia.tools import resolve_linkfinder_cmd

    if resolve_linkfinder_cmd():
        return True

    print("[+] Installing LinkFinder via pip...")
    result = _run([sys.executable, "-m", "pip", "install", "git+https://github.com/GerbenJavado/LinkFinder.git"])
    if result.returncode != 0:
        print(f"[!] Failed to install LinkFinder: {result.stderr.strip()}")
        return False

    if resolve_linkfinder_cmd():
        print("[+] LinkFinder available via binary or python -m linkfinder.")
        return True

    print("[!] LinkFinder installed but not resolvable. Please verify venv/bin or python -m linkfinder.")
    return False


def install_katana() -> str | None:
    """Attempt to install katana via Go."""
    from gaia.tools import get_tools_dir, resolve_tool

    existing = resolve_tool("katana")
    if existing:
        return existing

    if shutil.which("go") is None:
        print("[!] Go compiler not found. Install Go or set GAIA_DISABLE_KATANA=true to skip katana.")
        return None

    print("[+] Installing katana via Go...")
    result = _run(["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"])
    if result.returncode != 0:
        print(f"[!] Failed to install katana: {result.stderr.strip()}")
        return None

    go_path = _go_bin_path()
    if go_path:
        katana_bin = Path(go_path) / "katana"
        if katana_bin.exists():
            _copy_to_tools_dir(katana_bin, "katana")
            return str(katana_bin)
    tools_dir = get_tools_dir()
    if (tools_dir / "katana").exists():
        return str(tools_dir / "katana")
    if shutil.which("katana"):
        return shutil.which("katana")
    return None


__all__ = ["install_gau", "install_arjun", "install_linkfinder", "install_katana"]
