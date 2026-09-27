# ADR 0001: Using Semgrep for SAST Analysis

**Date**: 2024-01-01
**Status**: Accepted
**Deciders**: Platform Team

## Context

The secure SDLC platform requires a Static Application Security Testing (SAST) tool
that can be invoked programmatically as part of the AI agent pipeline.

## Decision Drivers

- Must support Python, JavaScript, TypeScript, Java, Go
- Must provide structured JSON output for agent consumption
- Must include CWE and OWASP category metadata on findings
- Must be embeddable in a Python subprocess call
- Must have active security rule maintenance
- Must support custom rules for organization-specific patterns

## Considered Options

1. **Semgrep** — OSS SAST with extensive security rulesets
2. **Bandit** — Python-only SAST
3. **CodeQL** — GitHub-integrated, requires build
4. **Snyk Code** — Commercial, REST API only

## Decision Outcome

**Semgrep** was chosen because:

1. Supports all target languages via a single tool invocation
2. Outputs structured JSON with rule IDs, CWE metadata, and code snippets
3. `semgrep --config=auto` activates curated security rules including OWASP Top 10
4. Free tier supports CI/CD pipeline use cases
5. Custom rules can be added as YAML to scan for organization patterns
6. Subprocess invocation is straightforward: `semgrep --json --config=auto <file>`

## Consequences

- semgrep binary must be installed in agent-runtime Docker image
- Scan timeout must be configurable (default 120s) to avoid blocking pipelines
- Heuristic fallback required for environments where semgrep is unavailable
- semgrep `--config=auto` requires network access on first run to download rules
