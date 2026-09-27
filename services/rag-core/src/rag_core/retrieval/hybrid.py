"""Hybrid retrieval combining vector similarity and keyword search."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class RetrievedDocument:
    """A retrieved document from the knowledge base."""

    content: str
    source: str
    score: float
    metadata: dict[str, Any] | None = None


class HybridRetriever:
    """Hybrid retriever combining dense vector search and sparse keyword search.

    Falls back to static security knowledge when stores are unavailable.
    """

    def __init__(self, top_k: int = 5) -> None:
        self._top_k = top_k
        self._static_docs = self._load_static_docs()

    def _load_static_docs(self) -> list[dict[str, Any]]:
        """Load static security knowledge as fallback."""
        return [
            {
                "content": "SQL injection (CWE-89) occurs when user input is directly concatenated into SQL queries. Use parameterized queries or prepared statements. Example fix: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                "source": "OWASP-A03-Injection",
                "score": 0.95,
            },
            {
                "content": "Command injection (CWE-78) via subprocess with shell=True allows attackers to execute arbitrary shell commands. Always pass command as a list and avoid shell=True.",
                "source": "CWE-78-CommandInjection",
                "score": 0.93,
            },
            {
                "content": "Insecure deserialization (CWE-502): Never deserialize untrusted data with pickle, yaml.load, or Java ObjectInputStream. Use JSON for serialization of untrusted data.",
                "source": "OWASP-A08-DataIntegrity",
                "score": 0.91,
            },
            {
                "content": "Weak cryptographic algorithms (CWE-327): MD5 and SHA-1 are cryptographically broken. Use SHA-256 or SHA-3 for hashing. Use bcrypt, argon2, or scrypt for password hashing.",
                "source": "OWASP-A02-CryptoFailures",
                "score": 0.90,
            },
            {
                "content": "Hardcoded credentials (CWE-259): Never store passwords, API keys, or tokens in source code. Use environment variables, Azure Key Vault, or AWS Secrets Manager.",
                "source": "CWE-259-HardcodedCredentials",
                "score": 0.88,
            },
        ]

    async def retrieve(
        self,
        query: str,
        top_k: int | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[RetrievedDocument]:
        """Retrieve relevant security knowledge for the query.

        Attempts vector store retrieval first; falls back to static knowledge.

        Args:
            query: The search query (e.g., security finding description).
            top_k: Number of results to return (overrides instance default).
            filters: Optional metadata filters.

        Returns:
            List of RetrievedDocument objects sorted by relevance score.
        """
        k = top_k or self._top_k

        try:
            return await self._vector_retrieve(query, k, filters)
        except Exception as exc:
            logger.warning("vector_retrieval_failed_using_static", error=str(exc))
            return self._static_retrieve(query, k)

    async def _vector_retrieve(
        self,
        query: str,
        top_k: int,
        filters: dict[str, Any] | None,
    ) -> list[RetrievedDocument]:
        """Retrieve from vector store."""
        from rag_core.embeddings.local_bge import LocalBGEEmbedder
        from rag_core.stores.pgvector_store import PgVectorStore
        from rag_core.config.settings import get_rag_settings

        settings = get_rag_settings()
        embedder = LocalBGEEmbedder()
        query_embedding = await embedder.embed(query)

        store = PgVectorStore(connection_url=settings.database_url)
        results = await store.similarity_search(
            query_embedding=query_embedding,
            top_k=top_k,
            filters=filters,
        )
        return results

    def _static_retrieve(
        self, query: str, top_k: int
    ) -> list[RetrievedDocument]:
        """Return static security knowledge documents."""
        docs = self._static_docs[:top_k]
        return [
            RetrievedDocument(
                content=d["content"],
                source=d["source"],
                score=d["score"],
            )
            for d in docs
        ]
