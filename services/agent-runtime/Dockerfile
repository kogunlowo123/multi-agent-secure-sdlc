FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir semgrep

COPY --from=ghcr.io/astral-sh/uv:0.2.0 /uv /usr/local/bin/uv

ENV UV_SYSTEM_PYTHON=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src:/app/api_src

COPY services/agent-runtime/pyproject.toml ./
RUN uv pip install langgraph langchain-core litellm pydantic pydantic-settings \
    structlog gitpython sentence-transformers psycopg2-binary \
    pgvector sqlalchemy opentelemetry-sdk PyJWT cryptography 2>/dev/null || true

COPY services/agent-runtime/src/ /app/src/
COPY services/api/src/ /app/api_src/

CMD ["python", "-m", "agent_runtime"]
