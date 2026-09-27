# Multi-Agent Secure SDLC Platform

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-green.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-orange.svg)](https://github.com/langchain-ai/langgraph)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/kogunlowo123/multi-agent-secure-sdlc/actions/workflows/ci.yml/badge.svg)](https://github.com/kogunlowo123/multi-agent-secure-sdlc/actions/workflows/ci.yml)

An enterprise AI platform for **multi-agent secure software delivery** — AI agents that perform security-aware code review, SAST analysis, dependency scanning, and release gating for software pipelines.

## Overview

The platform orchestrates three specialized AI agents in a sequential pipeline:

```
Code Diff / Release Request
         │
         ▼
  ┌─────────────┐
  │code-reviewer│  AI-powered security code review
  │   (T1)      │  OWASP Top 10, CWE patterns, injection vectors
  └──────┬──────┘
         │ findings
         ▼
  ┌─────────────┐
  │sast-analyst │  SAST scan via semgrep
  │   (T1)      │  Security rulesets, CWE mapping, prioritization
  └──────┬──────┘
         │ sast_findings
         ▼
  ┌─────────────┐
  │release-gater│  Go/No-Go decision with evidence
  │   (T1)      │  Policy evaluation, blocker synthesis
  └─────────────┘
         │
         ▼
  Release Decision (GO | NO-GO) + Evidence Trail
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.12+ and [uv](https://github.com/astral-sh/uv)
- Azure subscription (for production deployment)

### Local Development

```bash
git clone https://github.com/kogunlowo123/multi-agent-secure-sdlc.git
cd multi-agent-secure-sdlc

# Configure environment
cp .env.example .env
# Edit .env with your Azure OpenAI credentials

# Start all services
make docker-up

# Run tests
make test
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/code/review` | Submit code diff for AI security review |
| `POST` | `/api/v1/release/gate` | Evaluate release readiness (go/no-go) |
| `POST` | `/api/v1/sast/scan` | Run SAST scan on code |
| `GET`  | `/api/v1/release/{id}/status` | Get release gate status |
| `GET`  | `/api/v1/health` | Health check |
| `GET`  | `/api/v1/readiness` | Readiness probe |

### Example: Code Review

```bash
curl -X POST http://localhost:8000/api/v1/code/review \
  -H "Content-Type: application/json" \
  -d '{
    "code_diff": "def login(user, pw):\n    q = f\"SELECT * FROM users WHERE user='"'"'{user}'"'"'\"\n    return db.execute(q)",
    "language": "python",
    "repository": "my-org/my-app",
    "commit_sha": "abc123"
  }'
```

### Example: Release Gate

```bash
curl -X POST http://localhost:8000/api/v1/release/gate \
  -H "Content-Type: application/json" \
  -d '{
    "release_id": "rel-2024-001",
    "repository": "my-org/my-app",
    "commit_sha": "abc123",
    "test_coverage": 85.5,
    "sast_passed": true,
    "required_approvals": 2,
    "approvals_received": 2
  }'
```

## Architecture

- **Primary Cloud**: Azure (AKS, PostgreSQL Flex, AI Search, Service Bus, Key Vault)
- **AI**: Azure OpenAI GPT-4o via LiteLLM
- **Orchestration**: LangGraph 0.2+ multi-agent pipeline
- **RAG**: pgvector + Azure AI Search hybrid retrieval
- **SAST**: semgrep with security rulesets
- **API**: FastAPI + uvicorn
- **Observability**: OpenTelemetry + Grafana

## Configuration

See [`.env.example`](.env.example) for all configuration options.

Key settings:

| Variable | Description |
|----------|-------------|
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI resource endpoint |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key |
| `DATABASE_URL` | PostgreSQL connection string |
| `SECRET_KEY` | JWT signing key (min 32 chars) |

## Development

```bash
make install-dev    # Install dependencies
make format         # Format code
make lint           # Lint and type-check
make test           # Run all tests
make coverage       # Test coverage report
make semgrep        # SAST scan
```

## Infrastructure (Terraform)

```bash
cd infra/envs/azure/dev
terraform init
terraform plan
terraform apply
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting.

## License

Apache 2.0 — see [LICENSE](LICENSE).
