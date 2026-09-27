"""Local BGE embeddings using sentence-transformers."""
from __future__ import annotations

import asyncio
from functools import lru_cache

import structlog

from rag_core.embeddings.base import BaseEmbedder

logger = structlog.get_logger(__name__)


class LocalBGEEmbedder(BaseEmbedder):
    """Local embedding model using BGE via sentence-transformers.

    Uses BAAI/bge-small-en-v1.5 by default — a small, fast model
    suitable for security document retrieval.
    """

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        self._model_name = model_name
        self._model = None

    def _get_model(self):
        """Lazy-load the sentence transformer model."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            logger.info("loading_embedding_model", model=self._model_name)
            self._model = SentenceTransformer(self._model_name)
        return self._model

    @property
    def dimension(self) -> int:
        """Return the embedding dimension."""
        return 384  # bge-small-en-v1.5

    async def embed(self, text: str) -> list[float]:
        """Embed a single text string."""
        loop = asyncio.get_event_loop()
        model = self._get_model()
        embedding = await loop.run_in_executor(
            None, lambda: model.encode([text], normalize_embeddings=True)[0]
        )
        return embedding.tolist()

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts."""
        loop = asyncio.get_event_loop()
        model = self._get_model()
        embeddings = await loop.run_in_executor(
            None,
            lambda: model.encode(texts, normalize_embeddings=True, batch_size=32),
        )
        return [e.tolist() for e in embeddings]
