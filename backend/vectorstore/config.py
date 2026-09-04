"""Qdrant configuration, environment driven like l3/config.py."""

from __future__ import annotations

import os

# ":memory:" runs an embedded Qdrant inside the process, which is handy for
# local runs and validation; point this at http://host:6333 for a real server.
QDRANT_URL: str = os.getenv("QDRANT_URL", ":memory:")
QDRANT_API_KEY: str = os.getenv("QDRANT_API_KEY", "")
QDRANT_COLLECTION: str = os.getenv("QDRANT_COLLECTION", "security_context")
QDRANT_TIMEOUT: int = int(os.getenv("QDRANT_TIMEOUT", "30"))

# Default number of context documents returned for one rule finding.
QDRANT_TOP_K: int = int(os.getenv("QDRANT_TOP_K", "3"))

# Hits below this cosine score are dropped so the future LLM stage is not fed
# unrelated context.
QDRANT_SCORE_THRESHOLD: float = float(os.getenv("QDRANT_SCORE_THRESHOLD", "0.5"))
