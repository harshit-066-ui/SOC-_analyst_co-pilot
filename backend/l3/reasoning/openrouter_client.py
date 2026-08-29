"""OpenRouter HTTP client.

Responsibilities
----------------
- Read OPENROUTER_API_KEY from the environment (never hardcoded).
- Accept a configurable model identifier via config.OPENROUTER_MODEL.
- Send a single chat-completion request and return the assistant message text.
- Raise LLMUnavailableError for all failure modes so the caller can degrade
  gracefully — the application must NEVER crash due to LLM unavailability.

No business logic here: prompt construction is handled by prompt_builder.py,
response parsing is handled by llm_engine.py.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from l3.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
    OPENROUTER_TIMEOUT,
)

logger = logging.getLogger(__name__)


class LLMUnavailableError(Exception):
    """Raised when the LLM is unreachable or returns an unusable response."""


class OpenRouterClient:
    """Thin wrapper around the OpenRouter chat-completions endpoint.

    Parameters
    ----------
    model:
        Override the model from config.  Useful for per-request model
        selection without changing the global default.
    """

    COMPLETIONS_PATH = "/chat/completions"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or OPENROUTER_MODEL
        self._api_key = OPENROUTER_API_KEY
        self._base_url = OPENROUTER_BASE_URL.rstrip("/")
        self._timeout = OPENROUTER_TIMEOUT

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> str:
        """Send a chat-completion request and return the assistant reply.

        Parameters
        ----------
        system_prompt:
            High-level grounding instructions for the model.
        user_prompt:
            The structured evidence payload for this specific analysis.
        temperature:
            Low temperature enforces more deterministic, grounded output.
        max_tokens:
            Upper bound on response length.

        Returns
        -------
        str
            Raw assistant message text (expected to be JSON).

        Raises
        ------
        LLMUnavailableError
            On any network failure, timeout, API error, or empty response.
        """
        if not self._api_key:
            raise LLMUnavailableError(
                "OPENROUTER_API_KEY is not set. "
                "Export the variable in your shell or .env file."
            )

        headers = self._build_headers()
        payload = self._build_payload(
            system_prompt, user_prompt, temperature, max_tokens
        )

        try:
            response = httpx.post(
                f"{self._base_url}{self.COMPLETIONS_PATH}",
                headers=headers,
                json=payload,
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise LLMUnavailableError(
                f"Request timed out after {self._timeout}s: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise LLMUnavailableError(
                f"Network error contacting OpenRouter: {exc}"
            ) from exc

        return self._extract_content(response)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://soc-analyst-copilot",
            "X-Title": "SOC Analyst Co-Pilot PART 3",
        }

    def _build_payload(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }

    def _extract_content(self, response: httpx.Response) -> str:
        """Parse the HTTP response and return the assistant message text."""
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500]
            raise LLMUnavailableError(
                f"OpenRouter returned HTTP {exc.response.status_code}: {body}"
            ) from exc

        try:
            data: dict[str, Any] = response.json()
        except Exception as exc:
            raise LLMUnavailableError(
                f"Failed to decode JSON from OpenRouter: {exc}"
            ) from exc

        # Handle API-level error envelope
        if "error" in data:
            err = data["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise LLMUnavailableError(f"OpenRouter API error: {msg}")

        try:
            content: str = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailableError(
                f"Unexpected OpenRouter response shape: {exc}\n"
                f"Response keys: {list(data.keys())}"
            ) from exc

        if not content or not content.strip():
            raise LLMUnavailableError("OpenRouter returned an empty response.")

        logger.debug(
            "OpenRouter call complete | model=%s | chars=%d",
            self.model,
            len(content),
        )
        return content
