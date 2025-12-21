"""Configuration defaults and loader for Gaia."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "Gaia/0.1.0"
DEFAULT_MAX_URLS = 2000


@dataclass
class Config:
    """Runtime configuration values."""

    request_timeout: float = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT


def load_config() -> Config:
    """Load configuration from environment variables with sane defaults."""
    timeout = float(os.getenv("GAIA_TIMEOUT", DEFAULT_TIMEOUT))
    user_agent = os.getenv("GAIA_USER_AGENT", DEFAULT_USER_AGENT)
    return Config(request_timeout=timeout, user_agent=user_agent)
