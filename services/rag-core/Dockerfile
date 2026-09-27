FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

RUN pip install --no-cache-dir \
    sentence-transformers psycopg2-binary pgvector sqlalchemy \
    pydantic pydantic-settings structlog opensearch-py httpx \
    gitpython pypdf beautifulsoup4 numpy

COPY services/rag-core/src/ /app/src/

CMD ["python", "-m", "rag_core"]
