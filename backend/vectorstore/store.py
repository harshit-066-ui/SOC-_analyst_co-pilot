"""Qdrant-backed store for curated security context.

    rule finding -> embeddings.embed_text -> Qdrant search -> context documents

Only this module knows about Qdrant; callers pass plain text and get plain
dicts back, exactly as they pass plain text to the embedding service.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from embeddings import embed_text, embed_texts, get_embedding_service
from vectorstore.config import (
    QDRANT_API_KEY,
    QDRANT_COLLECTION,
    QDRANT_SCORE_THRESHOLD,
    QDRANT_TIMEOUT,
    QDRANT_TOP_K,
    QDRANT_URL,
)

logger = logging.getLogger(__name__)

_NAMESPACE = uuid.UUID("6f0f4a4a-6a4b-5c2e-9d6a-2f9b1c0d3e4f")


class VectorStoreError(RuntimeError):
    """Raised when Qdrant cannot be reached or a request fails."""


@dataclass
class ContextDocument:
    """One curated piece of security context to index."""

    id: str
    content: str
    category: str = ""
    tags: list[str] = field(default_factory=list)

    def point_id(self) -> str:
        """Stable UUID for ``id`` so re-indexing updates instead of duplicates."""

        return str(uuid.uuid5(_NAMESPACE, self.id))


def _build_client(url: str) -> QdrantClient:
    if url == ":memory:":
        return QdrantClient(location=":memory:")
    return QdrantClient(
        url=url, api_key=QDRANT_API_KEY or None, timeout=QDRANT_TIMEOUT
    )


class SecurityContextStore:
    """Indexes and searches security context documents in Qdrant."""

    def __init__(
        self,
        url: str = QDRANT_URL,
        collection: str = QDRANT_COLLECTION,
        top_k: int = QDRANT_TOP_K,
        score_threshold: float = QDRANT_SCORE_THRESHOLD,
    ) -> None:
        self.url = url
        self.collection = collection
        self.top_k = top_k
        self.score_threshold = score_threshold

        self._client: QdrantClient | None = None
        self._lock = threading.Lock()
        self._collection_ready = False

    # ------------------------------------------------------------------
    # Connection / collection lifecycle
    # ------------------------------------------------------------------

    @property
    def client(self) -> QdrantClient:
        """The Qdrant client, connected on first access."""

        if self._client is None:
            with self._lock:
                if self._client is None:
                    logger.info("Connecting to Qdrant at %s", self.url)
                    try:
                        self._client = _build_client(self.url)
                    except Exception as exc:
                        raise VectorStoreError(
                            f"Could not connect to Qdrant at {self.url}: {exc}"
                        ) from exc
        return self._client

    def ensure_collection(self) -> None:
        """Create the collection with BGE-M3's dimension if it is missing."""

        if self._collection_ready:
            return

        dimension = get_embedding_service().dimension
        try:
            if not self.client.collection_exists(self.collection):
                logger.info(
                    "Creating Qdrant collection %s (dim=%d, cosine)",
                    self.collection,
                    dimension,
                )
                self.client.create_collection(
                    collection_name=self.collection,
                    vectors_config=qmodels.VectorParams(
                        size=dimension, distance=qmodels.Distance.COSINE
                    ),
                )
        except Exception as exc:
            raise VectorStoreError(
                f"Could not prepare collection {self.collection}: {exc}"
            ) from exc

        self._collection_ready = True

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def index_documents(self, documents: list[ContextDocument]) -> int:
        """Embed and upsert documents; returns how many points were written."""

        if not documents:
            return 0

        self.ensure_collection()
        vectors = embed_texts([doc.content for doc in documents])
        points = [
            qmodels.PointStruct(
                id=doc.point_id(),
                vector=vector,
                payload={
                    "doc_id": doc.id,
                    "content": doc.content,
                    "category": doc.category,
                    "tags": doc.tags,
                },
            )
            for doc, vector in zip(documents, vectors)
        ]

        try:
            self.client.upsert(
                collection_name=self.collection, points=points, wait=True
            )
        except Exception as exc:
            raise VectorStoreError(f"Upsert failed: {exc}") from exc

        logger.info("Indexed %d context documents", len(points))
        return len(points)

    def count(self) -> int:
        """Number of indexed documents."""

        self.ensure_collection()
        return self.client.count(self.collection, exact=True).count

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        text: str,
        top_k: int | None = None,
        category: str | None = None,
        score_threshold: float | None = None,
    ) -> list[dict[str, Any]]:
        """Return the context documents closest to ``text``.

        ``category`` filters on the payload field of the same name, so MITRE
        context can be requested without touching IOC context.
        """

        self.ensure_collection()
        query_filter = None
        if category:
            query_filter = qmodels.Filter(
                must=[
                    qmodels.FieldCondition(
                        key="category", match=qmodels.MatchValue(value=category)
                    )
                ]
            )

        threshold = (
            self.score_threshold if score_threshold is None else score_threshold
        )
        try:
            response = self.client.query_points(
                collection_name=self.collection,
                query=embed_text(text),
                limit=top_k or self.top_k,
                query_filter=query_filter,
                score_threshold=threshold,
                with_payload=True,
            )
        except Exception as exc:
            raise VectorStoreError(f"Search failed: {exc}") from exc

        return [
            {
                "id": point.payload.get("doc_id"),
                "content": point.payload.get("content"),
                "category": point.payload.get("category"),
                "tags": point.payload.get("tags", []),
                "score": round(point.score, 4),
            }
            for point in response.points
        ]


_store: SecurityContextStore | None = None
_store_lock = threading.Lock()


def get_context_store() -> SecurityContextStore:
    """Process-wide store so the client and BGE-M3 are set up once."""

    global _store

    if _store is None:
        with _store_lock:
            if _store is None:
                _store = SecurityContextStore()
    return _store
