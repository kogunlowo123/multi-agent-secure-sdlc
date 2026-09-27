"""LangGraph multi-agent pipeline for secure SDLC.

Pipeline: code-reviewer -> sast-analyst -> release-gater
"""
from __future__ import annotations

import structlog
from langgraph.graph import END, START, StateGraph

from agent_runtime.orchestrator.state import AgentState

logger = structlog.get_logger(__name__)


async def code_reviewer_node(state: AgentState) -> dict:
    """Code reviewer agent node: performs AI-powered security code review."""
    from agent_runtime.agents.code_reviewer import CodeReviewerAgent

    log = logger.bind(session_id=state["session_id"], agent="code-reviewer")
    log.info("code_reviewer_starting", code_length=len(state.get("code_diff", "")))

    try:
        agent = CodeReviewerAgent()
        findings = await agent.review(
            code_diff=state["code_diff"],
            language=state["language"],
            repository=state.get("repository", ""),
        )
        log.info("code_reviewer_completed", finding_count=len(findings))
        return {
            "findings": findings,
            "current_agent": "sast-analyst",
        }
    except Exception as exc:
        log.error("code_reviewer_failed", error=str(exc))
        return {
            "findings": [],
            "errors": state.get("errors", []) + [f"code-reviewer: {exc}"],
            "current_agent": "sast-analyst",
        }


async def sast_analyst_node(state: AgentState) -> dict:
    """SAST analyst agent node: runs semgrep and interprets findings."""
    from agent_runtime.agents.sast_analyst import SASTAnalystAgent

    log = logger.bind(session_id=state["session_id"], agent="sast-analyst")
    log.info("sast_analyst_starting")

    try:
        agent = SASTAnalystAgent()
        sast_findings = await agent.analyze(
            code=state["code_diff"],
            language=state["language"],
        )
        log.info("sast_analyst_completed", finding_count=len(sast_findings))
        return {
            "sast_findings": sast_findings,
            "current_agent": "release-gater",
        }
    except Exception as exc:
        log.error("sast_analyst_failed", error=str(exc))
        return {
            "sast_findings": [],
            "errors": state.get("errors", []) + [f"sast-analyst: {exc}"],
            "current_agent": "release-gater",
        }


async def release_gater_node(state: AgentState) -> dict:
    """Release gater agent node: synthesizes all findings into a release decision."""
    from agent_runtime.agents.release_gater import ReleaseGaterAgent

    log = logger.bind(session_id=state["session_id"], agent="release-gater")
    log.info("release_gater_starting")

    try:
        agent = ReleaseGaterAgent()
        decision = await agent.evaluate(
            findings=state.get("findings", []),
            sast_findings=state.get("sast_findings", []),
            metadata=state.get("metadata", {}),
            errors=state.get("errors", []),
        )
        log.info("release_gater_completed", decision=decision.get("decision"))
        return {
            "release_decision": decision,
            "current_agent": "done",
        }
    except Exception as exc:
        log.error("release_gater_failed", error=str(exc))
        return {
            "release_decision": {
                "decision": "NO-GO",
                "status": "BLOCKED",
                "blockers": [f"Release gater encountered an error: {exc}"],
                "warnings": [],
                "evidence": {},
            },
            "errors": state.get("errors", []) + [f"release-gater: {exc}"],
            "current_agent": "done",
        }


def build_secure_sdlc_graph() -> StateGraph:
    """Build and compile the secure SDLC LangGraph pipeline.

    Returns a compiled StateGraph with the following nodes:
    - code-reviewer: AI-powered security code review
    - sast-analyst: SAST scan and interpretation
    - release-gater: Release readiness evaluation

    The pipeline is sequential: START -> code-reviewer -> sast-analyst -> release-gater -> END
    """
    workflow = StateGraph(AgentState)

    workflow.add_node("code-reviewer", code_reviewer_node)
    workflow.add_node("sast-analyst", sast_analyst_node)
    workflow.add_node("release-gater", release_gater_node)

    workflow.add_edge(START, "code-reviewer")
    workflow.add_edge("code-reviewer", "sast-analyst")
    workflow.add_edge("sast-analyst", "release-gater")
    workflow.add_edge("release-gater", END)

    return workflow.compile()
