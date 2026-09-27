"""Application configuration using pydantic-settings."""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = Field(default="development", description="Application environment")
    log_level: str = Field(default="INFO", description="Log level")
    secret_key: str = Field(
        default="change-me-in-production-32chars-x",
        description="JWT secret key (minimum 32 characters)",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiry_seconds: int = Field(default=3600, description="JWT token expiry in seconds")

    database_url: str = Field(
        default="postgresql://sdlc_user:password@localhost:5432/secure_sdlc",
        description="PostgreSQL connection URL",
    )

    azure_openai_endpoint: str = Field(default="", description="Azure OpenAI endpoint")
    azure_openai_api_key: str = Field(default="", description="Azure OpenAI API key")
    azure_openai_deployment_name: str = Field(
        default="gpt-4o", description="Azure OpenAI deployment name"
    )
    azure_openai_api_version: str = Field(
        default="2024-02-01", description="Azure OpenAI API version"
    )
    azure_openai_embedding_deployment: str = Field(
        default="text-embedding-3-large",
        description="Azure OpenAI embedding deployment",
    )

    azure_ai_search_endpoint: str = Field(default="", description="Azure AI Search endpoint")
    azure_ai_search_key: str = Field(default="", description="Azure AI Search key")
    azure_ai_search_index: str = Field(
        default="secure-sdlc-index", description="Azure AI Search index name"
    )

    rate_limit_per_minute: int = Field(
        default=60, description="Rate limit requests per minute per client IP"
    )

    semgrep_timeout: int = Field(default=120, description="Semgrep scan timeout in seconds")

    otel_service_name: str = Field(
        default="multi-agent-secure-sdlc", description="OpenTelemetry service name"
    )
    otel_exporter_otlp_endpoint: str = Field(
        default="http://localhost:4317",
        description="OpenTelemetry OTLP gRPC endpoint",
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
