"""Qdrant knowledge store.

    knowledge chunk -> embeddings.embed_texts -> Qdrant point
    security query  -> embeddings.embed_text  -> Qdrant search -> chunks

Only this module talks to Qdrant; callers pass plain text plus metadata and
get plain dicts back. Embeddings are always produced by the BGE-M3 service in
``backend/embeddings`` — nothing here builds vectors itself.
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
    IN_MEMORY,
    QDRANT_API_KEY,
    QDRANT_COLLECTION,
    QDRANT_SCORE_THRESHOLD,
    QDRANT_TIMEOUT,
    QDRANT_TOP_K,
    resolve_location,
)

logger = logging.getLogger(__name__)

_NAMESPACE = uuid.UUID("6f0f4a4a-6a4b-5c2e-9d6a-2f9b1c0d3e4f")

# Payload keys that are indexed for every document when known. Anything else a
# caller supplies is kept under "metadata" rather than being dropped.
PAYLOAD_FIELDS = (
    "source",
    "title",
    "section",
    "category",
    "technique_id",
    "tactic",
    "cve",
    "cwe",
    "rule_id",
    "platform",
    "severity",
)


class VectorStoreError(RuntimeError):
    """Raised for invalid input, connection problems or failed Qdrant calls."""


@dataclass
class KnowledgeDocument:
    """One cybersecurity knowledge chunk to store.

    Only ``document_id`` and ``text`` are required; every other field is
    written to the payload solely when it is actually known.
    """

    document_id: str
    text: str
    source: str = ""
    title: str = ""
    section: str = ""
    category: str = ""
    technique_id: str = ""
    tactic: str = ""
    cve: str = ""
    cwe: str = ""
    rule_id: str = ""
    platform: str = ""
    severity: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def point_id(self) -> str:
        """Deterministic UUID for ``document_id``.

        Qdrant only accepts integers or UUIDs, and a stable one means
        re-ingesting the same document updates its point instead of adding a
        duplicate.
        """

        return str(uuid.uuid5(_NAMESPACE, self.document_id))

    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "document_id": self.document_id,
            "text": self.text,
        }
        for name in PAYLOAD_FIELDS:
            value = getattr(self, name)
            if value:
                payload[name] = value
        if self.tags:
            payload["tags"] = list(self.tags)
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


def _build_filter(filters: dict[str, Any] | None) -> qmodels.Filter | None:
    """Turn ``{"platform": "Linux"}`` into a Qdrant payload filter."""

    if not filters:
        return None

    conditions = [
        qmodels.FieldCondition(key=key, match=qmodels.MatchValue(value=value))
        for key, value in filters.items()
    ]
    return qmodels.Filter(must=conditions)


class KnowledgeStore:
    """Owns the Qdrant collection of cybersecurity knowledge."""

    def __init__(
        self,
        location: str | None = None,
        collection: str = QDRANT_COLLECTION,
        top_k: int = QDRANT_TOP_K,
        score_threshold: float = QDRANT_SCORE_THRESHOLD,
    ) -> None:
        self.location = location or resolve_location()
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
                    logger.info("Connecting to Qdrant at %s", self.location)
                    try:
                        if self.location == IN_MEMORY:
                            self._client = QdrantClient(location=IN_MEMORY)
                        else:
                            self._client = QdrantClient(
                                url=self.location,
                                api_key=QDRANT_API_KEY or None,
                                timeout=QDRANT_TIMEOUT,
                            )
                    except Exception as exc:
                        raise VectorStoreError(
                            f"Could not connect to Qdrant at "
                            f"{self.location}: {exc}"
                        ) from exc
        return self._client

    @property
    def dimension(self) -> int:
        """Vector size the collection must use, taken from BGE-M3 itself."""

        return get_embedding_service().dimension

    def collection_exists(self) -> bool:
        try:
            return self.client.collection_exists(self.collection)
        except Exception as exc:
            raise VectorStoreError(
                f"Could not reach Qdrant at {self.location}: {exc}"
            ) from exc

    def create_collection(self, recreate: bool = False) -> None:
        """Create the collection if needed, sized from the embedding model.

        An existing collection whose vector size differs from BGE-M3's output
        is reported instead of being written to, since those points could
        never be searched with our embeddings.
        """

        dimension = self.dimension

        try:
            if recreate and self.collection_exists():
                logger.warning("Dropping collection %s", self.collection)
                self.client.delete_collection(self.collection)

            if not self.collection_exists():
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
            else:
                existing = self.client.get_collection(
                    self.collection
                ).config.params.vectors.size
                if existing != dimension:
                    raise VectorStoreError(
                        f"Collection {self.collection} stores {existing}-dim "
                        f"vectors but the embedding model produces {dimension}; "
                        "use a different QDRANT_COLLECTION or recreate it"
                    )
        except VectorStoreError:
            raise
        except Exception as exc:
            raise VectorStoreError(
                f"Could not prepare collection {self.collection}: {exc}"
            ) from exc

        self._collection_ready = True

    def ensure_collection(self) -> None:
        if not self._collection_ready:
            self.create_collection()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def upsert_documents(self, documents: list[KnowledgeDocument]) -> int:
        """Embed a batch of documents and write them; returns points written."""

        if not documents:
            return 0

        for index, document in enumerate(documents):
            if not document.document_id:
                raise VectorStoreError(f"Document at index {index} has no id")
            if not isinstance(document.text, str) or not document.text.strip():
                raise VectorStoreError(
                    f"Document {document.document_id} has no text to embed"
                )

        self.ensure_collection()

        # One embedding call for the whole batch, not one per document.
        vectors = embed_texts([document.text for document in documents])
        points = [
            qmodels.PointStruct(
                id=document.point_id(),
                vector=vector,
                payload=document.payload(),
            )
            for document, vector in zip(documents, vectors)
        ]

        try:
            self.client.upsert(
                collection_name=self.collection, points=points, wait=True
            )
        except Exception as exc:
            raise VectorStoreError(f"Upsert failed: {exc}") from exc

        logger.info(
            "Upserted %d knowledge documents into %s",
            len(points),
            self.collection,
        )
        return len(points)

    def delete(self, document_ids: list[str]) -> int:
        """Delete documents by their original ids; returns ids requested."""

        if not document_ids:
            return 0

        self.ensure_collection()
        point_ids = [
            str(uuid.uuid5(_NAMESPACE, document_id))
            for document_id in document_ids
        ]
        try:
            self.client.delete(
                collection_name=self.collection,
                points_selector=qmodels.PointIdsList(points=point_ids),
                wait=True,
            )
        except Exception as exc:
            raise VectorStoreError(f"Delete failed: {exc}") from exc

        logger.info("Deleted %d documents from %s", len(point_ids), self.collection)
        return len(point_ids)

    def count(self) -> int:
        """Number of stored documents."""

        self.ensure_collection()
        try:
            return self.client.count(self.collection, exact=True).count
        except Exception as exc:
            raise VectorStoreError(f"Count failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        top_k: int | None = None,
        filters: dict[str, Any] | None = None,
        score_threshold: float | None = None,
    ) -> list[dict[str, Any]]:
        """Return the knowledge chunks closest to ``query``.

        ``filters`` is an optional payload match, e.g.
        ``{"platform": "Linux"}`` or ``{"technique_id": "T1078"}``; plain
        semantic search runs without it.
        """

        if not isinstance(query, str) or not query.strip():
            raise VectorStoreError("Search query must be a non-empty string")

        limit = self.top_k if top_k is None else top_k
        if not isinstance(limit, int) or limit < 1:
            raise VectorStoreError(f"top_k must be a positive integer, got {top_k!r}")

        self.ensure_collection()
        threshold = (
            self.score_threshold if score_threshold is None else score_threshold
        )

        try:
            response = self.client.query_points(
                collection_name=self.collection,
                query=embed_text(query),
                limit=limit,
                query_filter=_build_filter(filters),
                score_threshold=threshold,
                with_payload=True,
            )
        except Exception as exc:
            raise VectorStoreError(f"Search failed: {exc}") from exc

        return [
            {
                "id": point.payload.get("document_id"),
                "score": round(point.score, 4),
                "text": point.payload.get("text", ""),
                "payload": {
                    key: value
                    for key, value in point.payload.items()
                    if key not in ("document_id", "text")
                },
            }
            for point in response.points
        ]


_store: KnowledgeStore | None = None
_store_lock = threading.Lock()


def get_knowledge_store() -> KnowledgeStore:
    """Process-wide store so the client and BGE-M3 are set up once."""

    global _store

    if _store is None:
        with _store_lock:
            if _store is None:
                _store = KnowledgeStore()
    return _store
