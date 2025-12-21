"""Subprocess helpers with Gaia debug-aware logging."""

from __future__ import annotations

import subprocess
from typing import Iterable, Optional

from gaia.logging_utils import summarize_cmd_failure, warn, debug


def run_cmd(cmd: Iterable[str], input_data: str | None = None, timeout: Optional[float] = None) -> subprocess.CompletedProcess[str]:
    cmd_list = list(cmd)
    debug(f"Running command: {' '.join(cmd_list)}")
    result = subprocess.run(
        cmd_list,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        warn(summarize_cmd_failure(cmd_list, result.returncode, result.stdout or "", result.stderr or ""))
    return result


__all__ = ["run_cmd"]
