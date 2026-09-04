"""BGE-M3 embedding layer — turns security text into dense vectors.

Consumed later by the Qdrant retrieval stage; nothing here knows about a
vector database.
"""

from embeddings.service import (
    EmbeddingError,
    EmbeddingService,
    embed_text,
    embed_texts,
    get_embedding_service,
)
from embeddings.text_builder import alert_to_text, assessment_to_text

__all__ = [
    "EmbeddingError",
    "EmbeddingService",
    "alert_to_text",
    "assessment_to_text",
    "embed_text",
    "embed_texts",
    "get_embedding_service",
]
