"""Code review request and response schemas."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Security finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASPCategory(str, Enum):
    """OWASP Top 10 2021 categories."""

    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


class Finding(BaseModel):
    """A security finding from code review."""

    id: str = Field(description="Unique finding identifier (UUID)")
    title: str = Field(description="Short, descriptive finding title")
    description: str = Field(description="Detailed description of the vulnerability")
    severity: FindingSeverity = Field(description="Finding severity level")
    owasp_category: Optional[OWASPCategory] = Field(
        default=None, description="OWASP Top 10 2021 category"
    )
    cwe_id: Optional[str] = Field(
        default=None, description="CWE identifier (e.g., CWE-89 for SQL Injection)"
    )
    file_path: Optional[str] = Field(
        default=None, description="Path to the affected file"
    )
    line_number: Optional[int] = Field(
        default=None, description="Affected line number in the file"
    )
    recommendation: str = Field(description="Concrete remediation recommendation")
    citations: list[str] = Field(
        default_factory=list,
        description="References to security standards (OWASP, CWE, NIST)",
    )


class CodeDiffRequest(BaseModel):
    """Request body for code security review."""

    code_diff: str = Field(
        description="Code diff in unified diff format or raw source code to review"
    )
    language: str = Field(
        description="Programming language (e.g., python, java, javascript, go)"
    )
    repository: Optional[str] = Field(
        default=None, description="Repository identifier (e.g., org/repo-name)"
    )
    commit_sha: Optional[str] = Field(
        default=None, description="Git commit SHA being reviewed"
    )
    context: Optional[str] = Field(
        default=None, description="Additional context to guide the security review"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "code_diff": (
                    "def login(username, password):\n"
                    "    query = f\"SELECT * FROM users WHERE username='{username}'\"\n"
                    "    return db.execute(query)"
                ),
                "language": "python",
                "repository": "my-org/my-app",
                "commit_sha": "abc123def456",
            }
        }
    }


class CodeReviewResult(BaseModel):
    """Result of an AI security code review."""

    review_id: str = Field(description="Unique review identifier")
    repository: str = Field(description="Repository that was reviewed")
    commit_sha: str = Field(description="Commit SHA that was reviewed")
    findings: list[Finding] = Field(description="Security findings from the review")
    severity_distribution: dict[str, int] = Field(
        description="Count of findings by severity level"
    )
    owasp_coverage: list[str] = Field(
        description="OWASP Top 10 categories identified in this review"
    )
    reviewed_at: datetime = Field(description="UTC timestamp when the review was completed")
