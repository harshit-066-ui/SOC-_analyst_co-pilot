"""Sources of curated context documents to index into Qdrant.

The curated CTI knowledge base already lives in ``l2/kb``; it is reused here
rather than duplicated, so keyword retrieval (L2) and semantic retrieval
(Qdrant) stay in sync.
"""

from __future__ import annotations

from l2.kb.cti_knowledge_base import KNOWLEDGE_BASE
from vectorstore.store import ContextDocument


def cti_documents() -> list[ContextDocument]:
    """The curated CTI knowledge base as indexable documents."""

    return [
        ContextDocument(
            id=entry["id"],
            content=entry["content"],
            category=entry.get("category", ""),
            tags=list(entry.get("tags", [])),
        )
        for entry in KNOWLEDGE_BASE
    ]
