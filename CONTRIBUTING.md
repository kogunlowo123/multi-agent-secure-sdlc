# Contributing to Multi-Agent Secure SDLC

Thank you for your interest in contributing!

## Development Setup

### Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) package manager
- Docker and Docker Compose
- semgrep (for SAST testing)

### Getting Started

```bash
git clone https://github.com/kogunlowo123/multi-agent-secure-sdlc.git
cd multi-agent-secure-sdlc
cp .env.example .env
# Edit .env with your configuration
make install-dev
make docker-up
```

### Running Tests

```bash
make test          # All tests
make test-unit     # Unit tests only
make test-security # Security tests
make coverage      # With coverage report
```

## Coding Standards

### Python Style

- Python 3.12+ type hints required
- Line length: 100 characters
- Formatter: `ruff format`
- Linter: `ruff check`
- Type checker: `mypy --strict`

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add SAST scan endpoint for TypeScript
fix: handle semgrep timeout in SASTScanTool
docs: update API documentation for /release/gate
test: add unit tests for release gater agent
refactor: extract finding severity logic to utils
security: fix SQL injection in session store
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make changes with tests
4. Ensure all tests pass: `make test`
5. Ensure lint passes: `make lint`
6. Submit a pull request against `main`

### Security Requirements

All PRs must:
- Pass `make semgrep` with no HIGH/CRITICAL findings
- Not introduce hardcoded secrets
- Include input validation for new API endpoints
- Have corresponding unit tests

## Architecture

This project follows Clean Architecture / Hexagonal Architecture principles:

- `services/api` - FastAPI HTTP interface (adapters)
- `services/agent-runtime` - LangGraph agent orchestration (domain)
- `services/rag-core` - RAG retrieval pipeline (infrastructure)

Domain logic lives in `agent-runtime` and is independent of HTTP framework.
