"""Embedding module configuration — environment driven, sensible defaults.

    EMBEDDING_MODEL       — model id, defaults to BAAI/bge-m3
    EMBEDDING_DEVICE      — "auto" (default), "cpu" or "cuda"
    EMBEDDING_BATCH_SIZE  — texts per forward pass, defaults to 8
    EMBEDDING_MAX_LENGTH  — max input tokens, defaults to 1024
    EMBEDDING_NORMALIZE   — L2-normalise vectors, defaults to true
"""

from __future__ import annotations

import os

EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "BAAI/bge-m3")
"""BGE-M3 is multilingual, handles up to 8192 tokens and is the model the
future Qdrant collection will be built against."""

EMBEDDING_DEVICE: str = os.getenv("EMBEDDING_DEVICE", "auto")
"""``auto`` picks CUDA when available and falls back to CPU."""

EMBEDDING_BATCH_SIZE: int = int(os.getenv("EMBEDDING_BATCH_SIZE", "8"))

EMBEDDING_MAX_LENGTH: int = int(os.getenv("EMBEDDING_MAX_LENGTH", "1024"))
"""BGE-M3 supports 8192 tokens; 1024 keeps CPU inference practical for the
short security findings this project embeds."""

EMBEDDING_NORMALIZE: bool = os.getenv("EMBEDDING_NORMALIZE", "true").lower() not in (
    "0",
    "false",
    "no",
)
"""Normalised vectors let cosine similarity be computed as a dot product,
which is what the Qdrant collection will use."""
