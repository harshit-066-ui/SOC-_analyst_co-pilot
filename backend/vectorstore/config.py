"""Qdrant configuration, environment driven like l3/config.py.

Local, Docker and remote Qdrant are all reachable through the same settings:
set ``QDRANT_URL`` for a full URL, or ``QDRANT_HOST`` / ``QDRANT_PORT`` for a
plain host. With neither, an embedded in-process Qdrant is used so the code
runs on a machine with no server at all.
"""

from __future__ import annotations

import os

QDRANT_HOST: str = os.getenv("QDRANT_HOST", "")
QDRANT_PORT: int = int(os.getenv("QDRANT_PORT", "6333"))
QDRANT_URL: str = os.getenv("QDRANT_URL", "")
QDRANT_API_KEY: str = os.getenv("QDRANT_API_KEY", "")
QDRANT_TIMEOUT: int = int(os.getenv("QDRANT_TIMEOUT", "30"))

QDRANT_COLLECTION: str = os.getenv("QDRANT_COLLECTION", "cybersecurity_knowledge")

# Default number of knowledge chunks returned for one query.
QDRANT_TOP_K: int = int(os.getenv("QDRANT_TOP_K", "3"))

# Hits below this cosine score are dropped so the future LLM stage is not fed
# unrelated context.
QDRANT_SCORE_THRESHOLD: float = float(os.getenv("QDRANT_SCORE_THRESHOLD", "0.5"))

# Embedded instance; no server needed.
IN_MEMORY = ":memory:"


def resolve_location() -> str:
    """Turn the configured host/port/url into a single location string."""

    if QDRANT_URL:
        return QDRANT_URL
    if QDRANT_HOST:
        return f"http://{QDRANT_HOST}:{QDRANT_PORT}"
    return IN_MEMORY
