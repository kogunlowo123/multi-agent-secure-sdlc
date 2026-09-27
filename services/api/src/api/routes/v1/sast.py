"""SAST scan API endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, HTTPException, status

from api.schemas.vulnerability import SASTFinding, SASTScanRequest, SASTScanResult

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post(
    "/sast/scan",
    response_model=SASTScanResult,
    status_code=status.HTTP_200_OK,
    summary="Run SAST vulnerability scan",
    description=(
        "Runs semgrep SAST analysis on the provided code using security rulesets. "
        "Detects injection vulnerabilities, hardcoded secrets, insecure crypto usage, "
        "path traversal, XXE, and deserialization vulnerabilities. "
        "Returns findings with CWE mappings and remediation guidance."
    ),
)
async def run_sast_scan(request: SASTScanRequest) -> SASTScanResult:
    """Run SAST analysis on provided code."""
    log = logger.bind(language=request.language)
    log.info("sast_scan_request_received", code_length=len(request.code))

    try:
        from agent_runtime.tools.sast_scan import SASTScanTool

        tool = SASTScanTool()
        findings: list[SASTFinding] = await tool.scan(
            code=request.code,
            language=request.language,
        )

        severity_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        result = SASTScanResult(
            scan_id=str(uuid.uuid4()),
            language=request.language,
            findings=findings,
            total_findings=len(findings),
            severity_breakdown=severity_counts,
            scanned_at=datetime.now(timezone.utc),
        )

        log.info(
            "sast_scan_completed",
            scan_id=result.scan_id,
            total_findings=result.total_findings,
            severity_breakdown=severity_counts,
        )
        return result

    except Exception as exc:
        log.error("sast_scan_failed", error=str(exc), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SAST scan failed: {exc}",
        ) from exc
