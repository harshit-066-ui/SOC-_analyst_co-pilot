"""L3 module configuration — all values driven by environment variables.

Never hardcode secrets here.  Set the following in your shell or .env file:

    OPENROUTER_API_KEY   — required for LLM calls
    OPENROUTER_PRIMARY_MODEL   — optional, defaults to deepseek/deepseek-v4-pro
    OPENROUTER_FALLBACK_MODEL  — optional, defaults to qwen/qwen-2.5-72b-instruct
    OPENROUTER_TIMEOUT   — optional, seconds (int), defaults to 60
    OPENROUTER_BASE_URL  — optional, defaults to https://openrouter.ai/api/v1
"""

from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load environment variables from .env
# ---------------------------------------------------------------------------

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"
if _ENV_FILE.exists():
    load_dotenv(dotenv_path=_ENV_FILE)
else:
    load_dotenv()

# ---------------------------------------------------------------------------
# OpenRouter settings
# ---------------------------------------------------------------------------

OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
"""Secret key — MUST be set in the environment, never committed to code."""

OPENROUTER_PRIMARY_MODEL: str = os.getenv(
    "OPENROUTER_PRIMARY_MODEL",
    os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4-pro"),
)
"""Primary model identifier for LLM reasoning."""

OPENROUTER_FALLBACK_MODEL: str = os.getenv(
    "OPENROUTER_FALLBACK_MODEL", "qwen/qwen-2.5-72b-instruct"
)
"""Fallback model identifier if primary model is unavailable or rate-limited."""

# Backward compatibility alias
OPENROUTER_MODEL: str = OPENROUTER_PRIMARY_MODEL
"""Alias pointing to the primary model for backward compatibility."""

OPENROUTER_TIMEOUT: int = int(os.getenv("OPENROUTER_TIMEOUT", "60"))
"""HTTP request timeout in seconds."""

OPENROUTER_MAX_TOKENS: int = int(os.getenv("OPENROUTER_MAX_TOKENS", "4096"))
"""Default upper bound on output tokens for LLM completions."""

OPENROUTER_BASE_URL: str = os.getenv(
    "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
)
"""Base URL for the OpenRouter API."""

LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
"""Logging level for the application."""

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
