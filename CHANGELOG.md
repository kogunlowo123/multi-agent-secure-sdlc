# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-01

### Added

- Multi-agent LangGraph pipeline: code-reviewer → sast-analyst → release-gater
- FastAPI service with endpoints:
  - `POST /api/v1/code/review` - AI-powered security code review
  - `POST /api/v1/release/gate` - Release gate evaluation
  - `POST /api/v1/sast/scan` - SAST vulnerability scan
  - `GET /api/v1/release/{id}/status` - Release status retrieval
  - `GET /api/v1/health` - Health check
  - `GET /api/v1/readiness` - Readiness probe
- SAST integration with semgrep (security rulesets)
- OWASP Top 10 vulnerability detection
- CWE pattern mapping for all findings
- RAG pipeline with pgvector and Azure AI Search support
- Azure OpenAI integration via LiteLLM
- JWT authentication middleware
- Per-client rate limiting middleware
- OpenTelemetry distributed tracing
- Terraform IaC for Azure (AKS, PostgreSQL Flex, AI Search, Service Bus, Key Vault)
- Helm charts for Kubernetes deployment
- ArgoCD app-of-apps GitOps configuration
- Kyverno security policies
- Sigma detection rules for security monitoring
- GitHub Actions CI/CD pipeline
- Production-ready Docker images
- Comprehensive test suite (unit, integration, security)

[Unreleased]: https://github.com/kogunlowo123/multi-agent-secure-sdlc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kogunlowo123/multi-agent-secure-sdlc/releases/tag/v0.1.0
