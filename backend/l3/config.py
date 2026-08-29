"""L3 module configuration — all values driven by environment variables.

Never hardcode secrets here.  Set the following in your shell or .env file:

    OPENROUTER_API_KEY   — required for LLM calls
    OPENROUTER_MODEL     — optional, defaults to anthropic/claude-3-haiku
    OPENROUTER_TIMEOUT   — optional, seconds (int), defaults to 60
    OPENROUTER_BASE_URL  — optional, defaults to https://openrouter.ai/api/v1
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# OpenRouter settings
# ---------------------------------------------------------------------------

OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
"""Secret key — MUST be set in the environment, never committed to code."""

OPENROUTER_MODEL: str = os.getenv(
    "OPENROUTER_MODEL", "anthropic/claude-3-haiku"
)
"""Model identifier passed to the OpenRouter completions endpoint."""

OPENROUTER_TIMEOUT: int = int(os.getenv("OPENROUTER_TIMEOUT", "60"))
"""HTTP request timeout in seconds."""

OPENROUTER_BASE_URL: str = os.getenv(
    "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
)
"""Base URL for the OpenRouter API."""

# ---------------------------------------------------------------------------
# L3 schema / feature flags
# ---------------------------------------------------------------------------

SCHEMA_VERSION: str = "1.0"

# Maximum characters of a single evidence item sent to the LLM (prevents
# token bloat from very large raw-event blobs).
MAX_EVIDENCE_ITEM_CHARS: int = 400

# Maximum number of CTI snippets included in a single prompt.
MAX_CTI_SNIPPETS: int = 5

# Evidence coverage threshold below which uncertainty must be "high".
LOW_EVIDENCE_THRESHOLD: float = 0.3
