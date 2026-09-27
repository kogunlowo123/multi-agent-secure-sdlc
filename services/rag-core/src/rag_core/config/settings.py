"""RAG core configuration."""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class RAGSettings(BaseSettings):
    """Configuration for the RAG core service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql://sdlc_user:password@localhost:5432/secure_sdlc"
    )

    azure_openai_endpoint: str = Field(default="")
    azure_openai_api_key: str = Field(default="")
    azure_openai_embedding_deployment: str = Field(default="text-embedding-3-large")
    azure_openai_api_version: str = Field(default="2024-02-01")

    azure_ai_search_endpoint: str = Field(default="")
    azure_ai_search_key: str = Field(default="")
    azure_ai_search_index: str = Field(default="secure-sdlc-index")

    embedding_model: str = Field(default="BAAI/bge-small-en-v1.5")
    embedding_dimension: int = Field(default=384)
    chunk_size: int = Field(default=512)
    chunk_overlap: int = Field(default=64)
    retrieval_top_k: int = Field(default=5)


@lru_cache
def get_rag_settings() -> RAGSettings:
    """Return cached RAG settings."""
    return RAGSettings()
