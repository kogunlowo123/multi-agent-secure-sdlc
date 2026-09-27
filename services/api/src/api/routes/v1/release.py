"""Release gate API endpoints."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, HTTPException, status

from api.schemas.release import ReleaseGateDecision, ReleaseGateRequest, ReleaseStatus

router = APIRouter()
logger = structlog.get_logger(__name__)

# In-memory store; replace with PostgreSQL in production
_release_store: dict[str, ReleaseGateDecision] = {}


@router.post(
    "/release/gate",
    response_model=ReleaseGateDecision,
    status_code=status.HTTP_200_OK,
    summary="Evaluate release readiness",
    description=(
        "Runs the full multi-agent pipeline (code-reviewer → sast-analyst → release-gater) "
        "and returns a go/no-go release decision with a complete evidence trail. "
        "A release is blocked if CRITICAL/HIGH findings exist, SAST gate fails, "
        "test coverage is below 70%, or required approvals are insufficient."
    ),
)
async def gate_release(request: ReleaseGateRequest) -> ReleaseGateDecision:
    """Evaluate whether a software release is ready to proceed."""
    log = logger.bind(release_id=request.release_id, repository=request.repository)
    log.info("release_gate_request_received")

    try:
        from agent_runtime.agents.release_gater import ReleaseGaterAgent
        from agent_runtime.agents.code_reviewer import CodeReviewerAgent
        from agent_runtime.agents.sast_analyst import SASTAnalystAgent

        code_findings: list = []
        sast_findings: list = []
        errors: list[str] = []

        if request.code_diff:
            try:
                code_agent = CodeReviewerAgent()
                code_findings = await code_agent.review(
                    code_diff=request.code_diff,
                    language=request.language or "python",
                    repository=request.repository,
                )
            except Exception as exc:
                errors.append(f"code-reviewer: {exc}")
                log.warning("code_review_step_failed", error=str(exc))

            try:
                sast_agent = SASTAnalystAgent()
                sast_findings = await sast_agent.analyze(
                    code=request.code_diff,
                    language=request.language or "python",
                )
            except Exception as exc:
                errors.append(f"sast-analyst: {exc}")
                log.warning("sast_analysis_step_failed", error=str(exc))

        gater = ReleaseGaterAgent()
        decision_data = await gater.evaluate(
            findings=code_findings,
            sast_findings=sast_findings,
            metadata={
                "release_id": request.release_id,
                "test_coverage": request.test_coverage,
                "sast_passed": request.sast_passed,
                "required_approvals": request.required_approvals,
                "approvals_received": request.approvals_received,
            },
            errors=errors,
        )

        result = ReleaseGateDecision(
            release_id=request.release_id,
            decision=decision_data["decision"],
            status=ReleaseStatus(decision_data["status"]),
            blockers=decision_data["blockers"],
            warnings=decision_data["warnings"],
            evidence=decision_data["evidence"],
            evaluated_at=datetime.now(timezone.utc),
        )

        _release_store[request.release_id] = result
        log.info(
            "release_gate_evaluated",
            decision=result.decision,
            blocker_count=len(result.blockers),
        )
        return result

    except Exception as exc:
        log.error("release_gate_failed", error=str(exc), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Release gate evaluation failed: {exc}",
        ) from exc


@router.get(
    "/release/{release_id}/status",
    response_model=ReleaseGateDecision,
    summary="Get release gate status",
)
async def get_release_status(release_id: str) -> ReleaseGateDecision:
    """Retrieve the decision for a previously evaluated release gate."""
    decision = _release_store.get(release_id)
    if not decision:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Release gate decision not found for release_id: {release_id}",
        )
    return decision
