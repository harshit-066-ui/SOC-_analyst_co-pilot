"""Functional check of the Qdrant layer.

    cd backend && python -m vectorstore.validate

Runs against whatever QDRANT_URL / QDRANT_HOST point at, or an embedded
instance when neither is set.
"""

from __future__ import annotations

import logging
import time

from embeddings import get_embedding_service
from vectorstore import (
    KnowledgeDocument,
    VectorStoreError,
    get_knowledge_store,
    seed_documents,
)
from vectorstore.store import KnowledgeStore

RELEVANT_QUERY = "Unauthorized privileged access detected on a Linux system."
UNRELATED_QUERY = "The cafeteria menu for next week has been published."


def show(hits: list[dict]) -> None:
    if not hits:
        print("   (no results)")
    for hit in hits:
        payload = hit["payload"]
        meta = {
            key: payload[key]
            for key in ("category", "technique_id", "platform", "severity")
            if key in payload
        }
        print(f"   {hit['score']:.3f} {hit['id']} {meta}")
        print(f"        {hit['text'][:88]}...")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    store = get_knowledge_store()
    print(f"location={store.location} collection={store.collection}")

    store.create_collection()
    print(f"collection_exists: {store.collection_exists()}")
    print(
        f"embedding dim={get_embedding_service().dimension} "
        f"collection dim={store.client.get_collection(store.collection).config.params.vectors.size}"
    )

    documents = seed_documents()
    start = time.perf_counter()
    print(
        f"upserted {store.upsert_documents(documents)} documents in "
        f"{time.perf_counter() - start:.1f}s | count={store.count()}"
    )
    store.upsert_documents(documents)
    print(f"count after re-ingest (stable ids): {store.count()}")

    print(f"\n1. relevant query: {RELEVANT_QUERY}")
    show(store.search(RELEVANT_QUERY))

    print(f"\n2. unrelated query: {UNRELATED_QUERY}")
    show(store.search(UNRELATED_QUERY))

    print("\n3. same query filtered to platform=Windows")
    show(store.search(RELEVANT_QUERY, filters={"platform": "Windows"}))

    print("\n4. top_k=1")
    show(store.search(RELEVANT_QUERY, top_k=1))

    print("\n5. filter that matches nothing (technique_id=T9999)")
    show(store.search(RELEVANT_QUERY, filters={"technique_id": "T9999"}))

    print("\nerror handling")
    for label, call in (
        ("empty query", lambda: store.search("   ")),
        ("top_k=0", lambda: store.search(RELEVANT_QUERY, top_k=0)),
        (
            "document without text",
            lambda: store.upsert_documents(
                [KnowledgeDocument(document_id="BAD-001", text="")]
            ),
        ),
        (
            "unreachable server",
            lambda: KnowledgeStore(location="http://127.0.0.1:1").count(),
        ),
    ):
        try:
            call()
            print(f"   {label}: NOT rejected")
        except VectorStoreError as exc:
            print(f"   {label}: {str(exc)[:70]}")

    removed = store.delete([documents[-1].document_id])
    print(f"\ndeleted {removed} document | count={store.count()}")
    store.upsert_documents([documents[-1]])


if __name__ == "__main__":
    main()
