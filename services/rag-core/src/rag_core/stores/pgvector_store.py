"""PostgreSQL pgvector vector store implementation."""
from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class PgVectorStore:
    """Vector store backed by PostgreSQL with pgvector extension."""

    def __init__(self, connection_url: str, table_name: str = "security_embeddings") -> None:
        self._connection_url = connection_url
        self._table_name = table_name

    async def similarity_search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[Any]:
        """Perform cosine similarity search against stored embeddings."""
        from rag_core.retrieval.hybrid import RetrievedDocument

        try:
            import psycopg2
            import json

            conn = psycopg2.connect(self._connection_url, connect_timeout=5)
            cursor = conn.cursor()

            embedding_str = "[" + ",".join(str(v) for v in query_embedding) + "]"
            query = f"""
                SELECT content, source, 1 - (embedding <=> '{embedding_str}'::vector) AS score
                FROM {self._table_name}
                ORDER BY embedding <=> '{embedding_str}'::vector
                LIMIT %s
            """
            cursor.execute(query, (top_k,))
            rows = cursor.fetchall()
            cursor.close()
            conn.close()

            return [
                RetrievedDocument(content=row[0], source=row[1], score=float(row[2]))
                for row in rows
            ]

        except Exception as exc:
            logger.warning("pgvector_search_failed", error=str(exc))
            raise

    async def upsert(
        self,
        content: str,
        embedding: list[float],
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Upsert a document with its embedding."""
        try:
            import psycopg2
            import json

            conn = psycopg2.connect(self._connection_url, connect_timeout=5)
            cursor = conn.cursor()

            embedding_str = "[" + ",".join(str(v) for v in embedding) + "]"
            cursor.execute(
                f"""
                INSERT INTO {self._table_name} (content, source, embedding, metadata)
                VALUES (%s, %s, %s::vector, %s)
                ON CONFLICT (source) DO UPDATE
                SET content = EXCLUDED.content,
                    embedding = EXCLUDED.embedding,
                    metadata = EXCLUDED.metadata
                """,
                (content, source, embedding_str, json.dumps(metadata or {})),
            )
            conn.commit()
            cursor.close()
            conn.close()

        except Exception as exc:
            logger.error("pgvector_upsert_failed", error=str(exc))
            raise
