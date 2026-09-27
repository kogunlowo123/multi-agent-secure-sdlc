"""Code review API endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, HTTPException, status

from api.schemas.code import (
    CodeDiffRequest,
    CodeReviewResult,
    Finding,
    FindingSeverity,
    OWASPCategory,
)

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post(
    "/code/review",
    response_model=CodeReviewResult,
    status_code=status.HTTP_200_OK,
    summary="Submit code diff for AI security review",
    description=(
        "Invokes the code-reviewer LangGraph agent to analyze the provided code diff "
        "for OWASP Top 10 vulnerabilities, CWE patterns, injection vectors, "
        "cryptographic weaknesses, and other security issues. Returns structured findings "
        "with severity ratings, remediation recommendations, and security knowledge citations."
    ),
)
async def review_code(request: CodeDiffRequest) -> CodeReviewResult:
    """Run AI-powered security code review on the provided code diff."""
    log = logger.bind(repository=request.repository, language=request.language)
    log.info("code_review_request_received", code_length=len(request.code_diff))

    try:
        from agent_runtime.agents.code_reviewer import CodeReviewerAgent

        agent = CodeReviewerAgent()
        raw_findings = await agent.review(
            code_diff=request.code_diff,
            language=request.language,
            repository=request.repository or "",
        )

        severity_distribution: dict[str, int] = {}
        owasp_coverage: list[str] = []
        findings: list[Finding] = []

        for f in raw_findings:
            sev = f.get("severity", "INFO")
            severity_distribution[sev] = severity_distribution.get(sev, 0) + 1

            owasp_raw = f.get("owasp_category")
            owasp = None
            if owasp_raw:
                try:
                    owasp = OWASPCategory(owasp_raw)
                    if owasp_raw not in owasp_coverage:
                        owasp_coverage.append(owasp_raw)
                except ValueError:
                    pass

            try:
                sev_enum = FindingSeverity(sev)
            except ValueError:
                sev_enum = FindingSeverity.INFO

            findings.append(
                Finding(
                    id=f.get("id", str(uuid.uuid4())),
                    title=f.get("title", "Security Finding"),
                    description=f.get("description", ""),
                    severity=sev_enum,
                    owasp_category=owasp,
                    cwe_id=f.get("cwe_id"),
                    file_path=f.get("file_path"),
                    line_number=f.get("line_number"),
                    recommendation=f.get("recommendation", "Review and remediate this finding."),
                    citations=f.get("citations", []),
                )
            )

        result = CodeReviewResult(
            review_id=str(uuid.uuid4()),
            repository=request.repository or "",
            commit_sha=request.commit_sha or "",
            findings=findings,
            severity_distribution=severity_distribution,
            owasp_coverage=owasp_coverage,
            reviewed_at=datetime.now(timezone.utc),
        )

        log.info(
            "code_review_completed",
            review_id=result.review_id,
            finding_count=len(findings),
        )
        return result

    except Exception as exc:
        log.error("code_review_failed", error=str(exc), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code review failed: {exc}",
        ) from exc
