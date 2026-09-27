FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.2.0 /uv /usr/local/bin/uv

ENV UV_SYSTEM_PYTHON=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src:/app/agent_runtime_src

FROM base AS builder

COPY services/api/pyproject.toml ./
RUN uv sync --frozen --no-dev 2>/dev/null || uv pip install \
    fastapi uvicorn pydantic pydantic-settings PyJWT httpx \
    opentelemetry-sdk opentelemetry-instrumentation-fastapi \
    opentelemetry-exporter-otlp structlog psycopg2-binary \
    redis langgraph langchain-core litellm gitpython \
    sentence-transformers pgvector sqlalchemy

FROM base AS final

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

COPY services/api/src/ /app/src/
COPY services/agent-runtime/src/ /app/agent_runtime_src/

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
