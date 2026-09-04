"""Manual check of the Qdrant layer.

    cd backend && python -m vectorstore.validate

Uses whatever QDRANT_URL points at (embedded ":memory:" by default).
"""

from __future__ import annotations

import logging
import time

from vectorstore import cti_documents, retrieve_for_text
from vectorstore.store import SecurityContextStore, VectorStoreError, get_context_store

QUERIES = [
    "Multiple failed authentication attempts against admin account",
    "An account gained unauthorized administrative privileges",
    "Outbound connection to 185.20.10.1",
]


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    store = get_context_store()
    print(f"url={store.url} collection={store.collection}")

    documents = cti_documents()
    start = time.perf_counter()
    written = store.index_documents(documents)
    print(f"indexed {written} documents in {time.perf_counter() - start:.1f}s")
    print(f"count after index: {store.count()}")

    # Re-indexing the same documents must not duplicate points.
    store.index_documents(documents)
    print(f"count after re-index: {store.count()}")

    for query in QUERIES:
        hits = retrieve_for_text(query)
        print(f"\nquery: {query}")
        for hit in hits:
            print(f"  {hit['score']:.3f} {hit['id']} [{hit['category']}] "
                  f"{hit['content'][:70]}...")
        if not hits:
            print("  (no hit above threshold)")

    filtered = store.search(QUERIES[1], category="mitre_technique")
    print(f"\ncategory filter mitre_technique -> "
          f"{[hit['id'] for hit in filtered]}")

    nonsense = store.search("chocolate cake recipe", score_threshold=0.8)
    print(f"unrelated query above 0.8: {[hit['id'] for hit in nonsense]}")

    try:
        SecurityContextStore(url="http://127.0.0.1:1").count()
    except VectorStoreError as exc:
        print(f"unreachable server rejected: {str(exc)[:60]}...")


if __name__ == "__main__":
    main()
