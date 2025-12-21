"""Lightweight logging and console helpers for Gaia."""

from __future__ import annotations

import os
import sys
import traceback
from typing import Any, Iterable

_DEBUG = os.getenv("GAIA_DEBUG", "false").lower() in {"1", "true", "yes", "on"}


def clear_console() -> None:
    """Clear console unless disabled."""
    if os.getenv("CI", "").lower() == "true":
        return
    if os.getenv("GAIA_NO_CLEAR", "").lower() in {"1", "true", "yes"}:
        return
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def _emit(prefix: str, message: str) -> None:
    sys.stdout.write(f"{prefix} {message}\n")
    sys.stdout.flush()


def info(msg: str) -> None:
    _emit("[*]", msg)


def success(msg: str) -> None:
    _emit("[+]", msg)


def warn(msg: str) -> None:
    _emit("[!]", msg)


def error(msg: str) -> None:
    _emit("[!]", msg)


def debug(msg: str) -> None:
    if _DEBUG:
        _emit("[d]", msg)


def is_truthy_env(name: str, default: bool = False) -> bool:
    if name not in os.environ:
        return default
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


def log_exception(prefix: str, exc: BaseException) -> None:
    if _DEBUG:
        _emit(prefix, f"{exc.__class__.__name__}: {exc}")
        traceback.print_exc()
    else:
        _emit(prefix, f"{exc.__class__.__name__}: {exc}")


def summarize_cmd_failure(cmd: Iterable[str], returncode: int, stdout: str, stderr: str) -> str:
    std_err_line = (stderr or "").splitlines()
    first_line = std_err_line[0] if std_err_line else ""
    cmd_str = " ".join(cmd)
    if _DEBUG:
        return f"cmd='{cmd_str}' exit={returncode} stdout='{stdout[:4000]}' stderr='{stderr[:4000]}'"
    return f"cmd='{cmd_str}' exit={returncode} err='{first_line}'"
