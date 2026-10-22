"""OpenRouter HTTP client with primary and fallback model support.

Responsibilities
----------------
- Read OPENROUTER_API_KEY from the environment (never hardcoded).
- Primary model (default: deepseek/deepseek-v4-pro) with graceful fallback to
  fallback model (default: qwen/qwen-2.5-72b-instruct) on recoverable upstream errors.
- Automatic recovery from provider response_format incompatibility (e.g. Novita).
- Automatic recovery from truncated outputs, provider interruptions, and malformed JSON.
- Raise LLMUnavailableError for all unrecoverable failure modes so the caller can degrade
  gracefully — the application must NEVER crash due to LLM unavailability.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

import httpx

from l3.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_FALLBACK_MODEL,
    OPENROUTER_MAX_TOKENS,
    OPENROUTER_PRIMARY_MODEL,
    OPENROUTER_TIMEOUT,
)

logger = logging.getLogger(__name__)


class LLMUnavailableError(Exception):
    """Raised when the LLM is unreachable or returns an unusable response."""


def _is_recoverable_error(exc: Exception) -> bool:
    """Determine if an error on the primary model warrants trying fallback."""
    if isinstance(exc, (httpx.TimeoutException, httpx.RequestError)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        # 429: Rate limited upstream (e.g. DeepInfra / OpenRouter)
        # 500, 502, 503, 504: Upstream server / provider outage
        # 404: Model unavailable or deprecated on provider
        if code in (429, 500, 502, 503, 504, 404):
            return True
        # 400: Upstream provider errors (excluding client authentication issues)
        if code == 400:
            text = exc.response.text.lower()
            if "auth" in text or "unauthorized" in text or "api key" in text or "credit" in text:
                return False
            return True
        # 401, 403: Authentication or permission errors — non-recoverable
        if code in (401, 403):
            return False
    if isinstance(exc, LLMUnavailableError):
        msg = str(exc).lower()
        if "api key" in msg or "unauthorized" in msg or "auth" in msg or "credit" in msg:
            return False
        return True
    if isinstance(exc, (ValueError, json.JSONDecodeError)):
        # Response parsing and schema-validation failures are recoverable via retry
        return True
    return False


def _categorize_failure(exc: Exception | None) -> str:
    """Classify an exception into a failure category for logging and corrective prompting."""
    if exc is None:
        return "none"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"http_{exc.response.status_code}"
    if isinstance(exc, httpx.RequestError):
        return "network_error"
    if isinstance(exc, (json.JSONDecodeError, ValueError)):
        return "invalid_json_or_schema"
    if isinstance(exc, LLMUnavailableError):
        msg = str(exc).lower()
        if "empty response" in msg:
            return "empty_response"
        if "truncated" in msg or "finish_reason: length" in msg:
            return "truncated"
        if "timeout" in msg or "timed out" in msg:
            return "timeout"
        if "api error" in msg:
            return "provider_api_error"
    return "general_error"


def _is_response_format_unsupported(exc: Exception) -> bool:
    """Check if an HTTP 400 error was specifically caused by response_format incompatibility."""
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 400:
        text = exc.response.text.lower()
        return (
            "response format" in text
            or "response_format" in text
            or "json_object is not supported" in text
            or "json_object" in text
        )
    if isinstance(exc, LLMUnavailableError):
        msg = str(exc).lower()
        return "response format" in msg or "json_object" in msg
    return False


class OpenRouterClient:
    """Wrapper around the OpenRouter chat-completions endpoint with model fallback.

    Parameters
    ----------
    model:
        Backward-compatibility override for primary model.
    primary_model:
        Override for the primary model identifier.
    fallback_model:
        Override for the fallback model identifier.
    """

    COMPLETIONS_PATH = "/chat/completions"

    def __init__(
        self,
        model: str | None = None,
        primary_model: str | None = None,
        fallback_model: str | None = None,
    ) -> None:
        self.primary_model = primary_model or model or OPENROUTER_PRIMARY_MODEL
        self.fallback_model = fallback_model or OPENROUTER_FALLBACK_MODEL
        self.last_used_model: str = self.primary_model
        self.last_finish_reason: str | None = None
        self.last_usage: dict[str, Any] = {}
        self.default_max_tokens = OPENROUTER_MAX_TOKENS
        self._api_key = OPENROUTER_API_KEY
        self._base_url = OPENROUTER_BASE_URL.rstrip("/")
        self._timeout = OPENROUTER_TIMEOUT
        # Cache of models where providers rejected response_format: {"type": "json_object"}
        self._unsupported_response_format_models: set[str] = set()

    @property
    def model(self) -> str:
        """The active or last used model identifier (for backward compatibility)."""
        return self.last_used_model or self.primary_model

    @model.setter
    def model(self, value: str) -> None:
        self.primary_model = value
        self.last_used_model = value

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int | None = None,
        validator: Callable[[str], Any] | None = None,
        max_retries_per_model: int = 1,
    ) -> str:
        """Send a chat-completion request with primary model and automatic fallback.

        Each model is attempted with corrective retries (up to
        ``max_retries_per_model``).  If the primary model fails with a
        recoverable error, the fallback model is tried with the same retry
        strategy.

        Parameters
        ----------
        system_prompt:
            High-level grounding instructions for the model.
        user_prompt:
            The structured evidence payload for this specific analysis.
        temperature:
            Low temperature enforces more deterministic, grounded output.
        max_tokens:
            Upper bound on response length (defaults to configured OPENROUTER_MAX_TOKENS).
        validator:
            Optional callback to strictly validate response format/schema.
            If validation fails, the attempt is treated as a recoverable failure.
        max_retries_per_model:
            Maximum number of corrective retries before failing.

        Returns
        -------
        str
            Raw assistant message text (validated JSON if validator supplied).

        Raises
        ------
        LLMUnavailableError
            When all configured models fail or when an unrecoverable error occurs.
        """
        if not self._api_key:
            raise LLMUnavailableError(
                "OPENROUTER_API_KEY is not set. "
                "Export the variable in your shell or .env file."
            )

        effective_max_tokens = (
            max_tokens if max_tokens is not None else self.default_max_tokens
        )

        # 1. Attempt Primary Model (with corrective retries)
        primary_content, primary_err = self._attempt_model(
            model=self.primary_model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            max_tokens=effective_max_tokens,
            validator=validator,
            max_retries_per_model=max_retries_per_model,
        )
        if primary_content is not None:
            self.last_used_model = self.primary_model
            return primary_content

        # primary_err is set and recoverable — try fallback
        # 2. Attempt Fallback Model (with corrective retries)
        if self.fallback_model and self.fallback_model != self.primary_model:
            logger.warning(
                "Primary model %s failed (%s); attempting fallback model %s",
                self.primary_model,
                primary_err,
                self.fallback_model,
            )
            fallback_content, fallback_err = self._attempt_model(
                model=self.fallback_model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=effective_max_tokens,
                validator=validator,
                max_retries_per_model=max_retries_per_model,
            )
            if fallback_content is not None:
                self.last_used_model = self.fallback_model
                logger.info("Fallback model %s completed successfully", self.fallback_model)
                return fallback_content

            # Both models failed
            logger.error(
                "Both primary (%s) and fallback (%s) models failed. "
                "Primary error: %s | Fallback error: %s",
                self.primary_model,
                self.fallback_model,
                primary_err,
                fallback_err,
            )
            raise LLMUnavailableError(
                f"Both primary model ({self.primary_model}) and fallback model "
                f"({self.fallback_model}) failed. "
                f"Primary: {primary_err}; Fallback: {fallback_err}"
            ) from fallback_err

        raise primary_err if isinstance(primary_err, LLMUnavailableError) else LLMUnavailableError(str(primary_err)) from primary_err

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _attempt_model(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        validator: Callable[[str], Any] | None,
        max_retries_per_model: int,
    ) -> tuple[str | None, Exception | None]:
        """Try a single model with corrective retries.

        Returns
        -------
        (content, error)
            On success: (content, None).
            On recoverable failure: (None, error).
            On unrecoverable failure: raises LLMUnavailableError immediately.
        """
        current_model_err: Exception | None = None

        for attempt in range(max_retries_per_model + 1):
            if attempt == 0:
                current_prompt = user_prompt
            else:
                category = _categorize_failure(current_model_err)
                current_prompt = (
                    f"{user_prompt}\n\n"
                    f"[CORRECTION REQUIRED]: Your previous response failed due to {category} "
                    f"({current_model_err}). Respond with ONLY a valid, complete JSON object "
                    f"conforming strictly to the requested schema. Keep the summary and reasoning "
                    f"concise to prevent truncation."
                )
                logger.info(
                    "Retrying model %s (attempt %d/%d) with corrective prompt (category: %s)",
                    model,
                    attempt + 1,
                    max_retries_per_model + 1,
                    category,
                )

            try:
                content = self._send_completion(
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=current_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )

                # Validate response content and schema if validator is provided
                if validator is not None:
                    validator(content)

                self.last_used_model = model
                logger.info(
                    "Model %s succeeded on attempt %d/%d (finish_reason=%s)",
                    model,
                    attempt + 1,
                    max_retries_per_model + 1,
                    self.last_finish_reason,
                )
                return content, None

            except Exception as exc:
                current_model_err = exc
                category = _categorize_failure(exc)
                logger.warning(
                    "Model %s attempt %d/%d failed (category=%s): %s",
                    model,
                    attempt + 1,
                    max_retries_per_model + 1,
                    category,
                    exc,
                )

                if not _is_recoverable_error(exc):
                    # Unrecoverable error (e.g. auth error, invalid key) -> raise immediately
                    logger.error(
                        "Model %s encountered unrecoverable error (%s): %s",
                        model,
                        category,
                        exc,
                    )
                    raise (
                        exc
                        if isinstance(exc, LLMUnavailableError)
                        else LLMUnavailableError(str(exc))
                    ) from exc

        # All retries exhausted with recoverable errors
        failure_msg = f"{model} failed after {max_retries_per_model + 1} attempt(s): {current_model_err}"
        logger.error("Model %s failed. %s", model, failure_msg)
        err = LLMUnavailableError(f"Model failed. {failure_msg}")
        err.__cause__ = current_model_err
        return None, err

    def _send_completion(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Send completion request to OpenRouter for a specific model."""
        headers = self._build_headers()
        send_response_format = model not in self._unsupported_response_format_models

        payload = self._build_payload(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            include_response_format=send_response_format,
        )

        try:
            response = httpx.post(
                f"{self._base_url}{self.COMPLETIONS_PATH}",
                headers=headers,
                json=payload,
                timeout=self._timeout,
            )
            return self._extract_content(response, model=model)
        except httpx.HTTPStatusError as exc:
            # Check for provider response_format incompatibility (e.g. Novita returning HTTP 400)
            if send_response_format and _is_response_format_unsupported(exc):
                logger.warning(
                    "Provider for model %s does not support response_format json_object; "
                    "retrying immediately with prompt-enforced JSON.",
                    model,
                )
                self._unsupported_response_format_models.add(model)
                fallback_payload = self._build_payload(
                    model=model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    include_response_format=False,
                )
                try:
                    retry_response = httpx.post(
                        f"{self._base_url}{self.COMPLETIONS_PATH}",
                        headers=headers,
                        json=fallback_payload,
                        timeout=self._timeout,
                    )
                    return self._extract_content(retry_response, model=model)
                except Exception as retry_exc:
                    self._handle_http_error(retry_exc, model)
            self._handle_http_error(exc, model)
        except httpx.TimeoutException as exc:
            raise LLMUnavailableError(
                f"Request for model {model} timed out after {self._timeout}s: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise LLMUnavailableError(
                f"Network error contacting OpenRouter for model {model}: {exc}"
            ) from exc

    def _handle_http_error(self, exc: Exception, model: str) -> None:
        """Sanitize and format HTTP errors without leaking credentials."""
        if isinstance(exc, httpx.HTTPStatusError):
            body = exc.response.text[:500]
            raise LLMUnavailableError(
                f"OpenRouter returned HTTP {exc.response.status_code} for model {model}: {body}"
            ) from exc
        raise exc

    def _build_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://soc-analyst-copilot",
            "X-Title": "SOC Analyst Co-Pilot PART 3",
        }

    def _build_payload(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        include_response_format: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if include_response_format:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _extract_content(self, response: httpx.Response, model: str) -> str:
        """Parse HTTP response and extract assistant message text."""
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500]
            raise LLMUnavailableError(
                f"OpenRouter returned HTTP {exc.response.status_code} for model {model}: {body}"
            ) from exc

        try:
            data: dict[str, Any] = response.json()
        except Exception as exc:
            raise LLMUnavailableError(
                f"Failed to decode JSON from OpenRouter for model {model}: {exc}"
            ) from exc

        # Handle API-level error envelope
        if "error" in data:
            err = data["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise LLMUnavailableError(f"OpenRouter API error for model {model}: {msg}")

        try:
            choice = data["choices"][0]
            content: str = choice["message"]["content"]
            finish_reason = choice.get("finish_reason")
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailableError(
                f"Unexpected OpenRouter response shape for model {model}: {exc}\n"
                f"Response keys: {list(data.keys())}"
            ) from exc

        usage = data.get("usage") or {}
        self.last_finish_reason = finish_reason
        self.last_usage = usage

        if not content or not content.strip():
            raise LLMUnavailableError(
                f"OpenRouter returned an empty response for model {model}."
            )

        if finish_reason == "length":
            raise LLMUnavailableError(
                f"OpenRouter response truncated for model {model} "
                f"(finish_reason: length, completion_tokens: {usage.get('completion_tokens')})."
            )

        logger.debug(
            "OpenRouter call complete | model=%s | finish_reason=%s | tokens=%s | chars=%d",
            model,
            finish_reason,
            usage.get("total_tokens"),
            len(content),
        )
        return content
