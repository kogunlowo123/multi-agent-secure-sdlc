"""Release gate request and response schemas."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ReleaseStatus(str, Enum):
    """Release gate status values."""

    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    PENDING = "PENDING"
    CONDITIONAL = "CONDITIONAL"


class ReleaseGateRequest(BaseModel):
    """Request body for release gate evaluation."""

    release_id: str = Field(description="Unique release identifier")
    repository: str = Field(description="Repository identifier (org/repo)")
    commit_sha: str = Field(description="Git commit SHA to evaluate for release")
    code_diff: Optional[str] = Field(
        default=None,
        description="Code changes to scan (if not already scanned separately)",
    )
    language: Optional[str] = Field(
        default="python", description="Primary programming language"
    )
    test_coverage: Optional[float] = Field(
        default=None,
        description="Test coverage percentage (0.0-100.0). Blocks if < 70%.",
    )
    sast_passed: Optional[bool] = Field(
        default=None,
        description="Whether a SAST scan has already passed for this commit",
    )
    required_approvals: int = Field(
        default=2,
        description="Number of code review approvals required before release",
    )
    approvals_received: int = Field(
        default=0,
        description="Number of approvals received so far",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "release_id": "rel-2024-001",
                "repository": "my-org/my-app",
                "commit_sha": "abc123def456",
                "test_coverage": 85.5,
                "sast_passed": True,
                "required_approvals": 2,
                "approvals_received": 2,
            }
        }
    }


class ReleaseGateDecision(BaseModel):
    """Decision from release gate evaluation."""

    release_id: str = Field(description="Release identifier")
    decision: str = Field(description="GO or NO-GO release decision")
    status: ReleaseStatus = Field(description="Detailed release status")
    blockers: list[str] = Field(
        default_factory=list,
        description="Issues that are blocking the release",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-blocking warnings to address",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Supporting evidence for the decision (findings, scores, metadata)",
    )
    evaluated_at: datetime = Field(
        description="UTC timestamp when the gate was evaluated"
    )
