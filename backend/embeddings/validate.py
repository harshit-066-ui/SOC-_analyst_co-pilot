"""Manual validation of the embedding service.

    cd backend && python -m embeddings.validate

Checks that the model loads, that single/batch embedding works, that the
dimensionality is stable, that invalid input is rejected, that the model is
reused across calls, and that cosine similarity ranks related security texts
above unrelated ones.
"""

from __future__ import annotations

import logging
import time

from embeddings.service import EmbeddingError, EmbeddingService, get_embedding_service

SIMILAR_A = "Unauthorized privileged access was detected."
SIMILAR_B = "An account gained unauthorized administrative privileges."
UNRELATED = "Normal user login successful."

STRUCTURED_FINDING = (
    "Rule ID: PRIV-001\n"
    "Finding: Unauthorized privileged access detected\n"
    "Severity: High\n"
    "Risk: Unauthorized privilege access\n"
    "Platform: Linux"
)


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5
    return dot / (norm_a * norm_b)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    service = get_embedding_service()
    print(f"model={service.model_name} device={service.device}")

    started = time.perf_counter()
    single = service.embed_text(SIMILAR_A)
    print(f"first call (includes model load): {time.perf_counter() - started:.1f}s")
    print(f"dimension: {len(single)}")

    started = time.perf_counter()
    batch = service.embed_texts([SIMILAR_A, SIMILAR_B, UNRELATED, STRUCTURED_FINDING])
    print(f"batch of {len(batch)} (model reused): {time.perf_counter() - started:.1f}s")
    print(f"dimensions: {sorted({len(vector) for vector in batch})}")
    print(f"model reused: {get_embedding_service() is service and service.is_loaded}")

    print(f"cos(similar A, similar B): {cosine(batch[0], batch[1]):.3f}")
    print(f"cos(similar A, unrelated): {cosine(batch[0], batch[2]):.3f}")
    print(f"cos(similar A, structured finding): {cosine(batch[0], batch[3]):.3f}")

    for invalid in ("", "   ", None):
        try:
            service.embed_texts([invalid])  # type: ignore[list-item]
        except EmbeddingError as exc:
            print(f"rejected {invalid!r}: {exc}")
        else:
            print(f"NOT REJECTED: {invalid!r}")

    print(f"empty list: {service.embed_texts([])}")

    cpu_service = EmbeddingService(device="cpu")
    print(f"explicit cpu device: {cpu_service.device}")


if __name__ == "__main__":
    main()
