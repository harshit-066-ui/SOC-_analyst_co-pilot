"""BGE-M3 embedding service.

The rest of the application only sees ``embed_text`` / ``embed_texts``; how
BGE-M3 is loaded stays here so the model can later back a Qdrant collection
without any caller changing.

    security text -> EmbeddingService -> BGE-M3 -> list[float]

The model is loaded lazily on first use and reused for every later call.
"""

from __future__ import annotations

import logging
import threading

from sentence_transformers import SentenceTransformer

from embeddings.config import (
    EMBEDDING_BATCH_SIZE,
    EMBEDDING_DEVICE,
    EMBEDDING_MAX_LENGTH,
    EMBEDDING_MODEL,
    EMBEDDING_NORMALIZE,
)

logger = logging.getLogger(__name__)


class EmbeddingError(RuntimeError):
    """Raised when the model cannot be loaded or a text cannot be embedded."""


def resolve_device(device: str = EMBEDDING_DEVICE) -> str:
    """Turn the configured device into a concrete torch device string."""

    if device != "auto":
        return device

    import torch

    return "cuda" if torch.cuda.is_available() else "cpu"


class EmbeddingService:
    """Loads BGE-M3 once and turns security text into dense vectors."""

    def __init__(
        self,
        model_name: str = EMBEDDING_MODEL,
        device: str = EMBEDDING_DEVICE,
        batch_size: int = EMBEDDING_BATCH_SIZE,
        max_length: int = EMBEDDING_MAX_LENGTH,
        normalize: bool = EMBEDDING_NORMALIZE,
    ) -> None:
        self.model_name = model_name
        self.device = resolve_device(device)
        self.batch_size = batch_size
        self.max_length = max_length
        self.normalize = normalize

        self._model: SentenceTransformer | None = None
        self._load_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Model lifecycle
    # ------------------------------------------------------------------

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def model(self) -> SentenceTransformer:
        """The loaded model, loading it on first access."""

        if self._model is None:
            with self._load_lock:
                if self._model is None:
                    self._model = self._load()
        return self._model

    def _load(self) -> SentenceTransformer:
        logger.info(
            "Loading embedding model %s on %s", self.model_name, self.device
        )
        try:
            model = SentenceTransformer(self.model_name, device=self.device)
        except Exception as exc:
            raise EmbeddingError(
                f"Could not load embedding model {self.model_name}: {exc}"
            ) from exc

        model.max_seq_length = self.max_length
        logger.info(
            "Embedding model ready | dimension=%d | max_seq_length=%d",
            model.get_sentence_embedding_dimension(),
            model.max_seq_length,
        )
        return model

    @property
    def dimension(self) -> int:
        """Vector length produced by the model (1024 for BGE-M3)."""

        return self.model.get_sentence_embedding_dimension()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def embed_text(self, text: str) -> list[float]:
        """Embed a single security text."""

        return self.embed_texts([text])[0]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Embed several security texts in batches.

        Raises
        ------
        EmbeddingError
            If any text is not a non-empty string, or inference fails.
        """

        if not texts:
            return []

        for index, text in enumerate(texts):
            if not isinstance(text, str) or not text.strip():
                raise EmbeddingError(
                    f"Text at index {index} must be a non-empty string"
                )

        try:
            vectors = self.model.encode(
                texts,
                batch_size=self.batch_size,
                normalize_embeddings=self.normalize,
                convert_to_numpy=True,
                show_progress_bar=False,
            )
        except Exception as exc:
            raise EmbeddingError(f"Embedding failed: {exc}") from exc

        return [vector.tolist() for vector in vectors]


_service: EmbeddingService | None = None
_service_lock = threading.Lock()


def get_embedding_service() -> EmbeddingService:
    """Process-wide service so BGE-M3 is loaded at most once."""

    global _service

    if _service is None:
        with _service_lock:
            if _service is None:
                _service = EmbeddingService()
    return _service


def embed_text(text: str) -> list[float]:
    """Module-level shortcut around the shared service."""

    return get_embedding_service().embed_text(text)


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Module-level shortcut around the shared service."""

    return get_embedding_service().embed_texts(texts)
