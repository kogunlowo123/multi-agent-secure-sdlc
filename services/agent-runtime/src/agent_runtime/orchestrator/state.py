"""LangGraph shared state definition for the secure SDLC multi-agent pipeline."""
from __future__ import annotations

from typing import Any, Optional, TypedDict


class AgentState(TypedDict):
    """Shared mutable state flowing through the secure SDLC agent pipeline.

    Attributes:
        session_id: Unique identifier for this pipeline execution session.
        code_diff: The code diff or source code submitted for review.
        language: Programming language of the code being analyzed.
        repository: Repository identifier (e.g., org/repo-name).
        commit_sha: Git commit SHA being evaluated.
        findings: Security findings from the code-reviewer agent.
        sast_findings: SAST findings from the sast-analyst agent.
        release_decision: Go/no-go decision from the release-gater agent.
        current_agent: Name of the currently executing agent node.
        errors: Accumulated errors from agent executions (non-fatal).
        metadata: Additional context (test_coverage, approvals, etc.).
    """

    session_id: str
    code_diff: str
    language: str
    repository: str
    commit_sha: str
    findings: list[dict[str, Any]]
    sast_findings: list[dict[str, Any]]
    release_decision: Optional[dict[str, Any]]
    current_agent: str
    errors: list[str]
    metadata: dict[str, Any]
