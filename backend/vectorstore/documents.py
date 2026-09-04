"""Knowledge documents available for ingestion.

Two sources, both optional for callers:

* ``seed_documents()`` - the small curated set in
  ``knowledge_config/seed_knowledge.json`` used for validation and local runs.
* ``cti_documents()``  - the curated CTI entries already in ``l2/kb`` reused
  as-is, so keyword retrieval (L2) and semantic retrieval share one corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from l2.kb.cti_knowledge_base import KNOWLEDGE_BASE
from vectorstore.store import KnowledgeDocument

SEED_FILE = Path(__file__).parent / "knowledge_config" / "seed_knowledge.json"


def _to_document(entry: dict[str, Any]) -> KnowledgeDocument:
    """Build a document, keeping unknown keys under ``metadata``."""

    known = {
        field: entry[field]
        for field in KnowledgeDocument.__dataclass_fields__
        if field in entry
    }
    extra = {key: value for key, value in entry.items() if key not in known}
    if extra:
        known.setdefault("metadata", {}).update(extra)
    return KnowledgeDocument(**known)


def seed_documents() -> list[KnowledgeDocument]:
    """The curated seed knowledge set."""

    entries = json.loads(SEED_FILE.read_text())
    return [_to_document(entry) for entry in entries]


def cti_documents() -> list[KnowledgeDocument]:
    """The L2 curated CTI knowledge base as knowledge documents."""

    return [
        KnowledgeDocument(
            document_id=entry["id"],
            text=entry["content"],
            source="l2_cti_kb",
            category=entry.get("category", ""),
            tags=list(entry.get("tags", [])),
        )
        for entry in KNOWLEDGE_BASE
    ]
