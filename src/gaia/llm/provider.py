"""LLM provider selection and LiteLLM client helper."""

from __future__ import annotations

import os
from typing import Callable, Optional

from litellm import completion


class NoLLMProvider(RuntimeError):
    """Raised when AI is requested but no provider/model is configured."""


def get_model_name() -> Optional[str]:
    """Resolve the model name from environment variables."""
    return (
        os.getenv("GAIA_LLM_MODEL")
        or os.getenv("OPENAI_MODEL")
        or os.getenv("LLM_MODEL")
    )


def get_llm_client() -> Optional[Callable[[str], str]]:
    """Return a callable that takes a prompt string and returns LLM text via LiteLLM."""
    model_name = get_model_name()
    if not model_name:
        return None

    def _client(prompt: str) -> str:
        try:
            resp = completion(
                model=model_name,
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )
            return resp["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001
            raise NoLLMProvider(f"LLM call failed: {exc}") from exc

    return _client
