"""Unit tests for the release gater agent."""
from __future__ import annotations

import pytest

from agent_runtime.agents.release_gater import ReleaseGaterAgent


@pytest.fixture
def gater() -> ReleaseGaterAgent:
    """Provide a ReleaseGaterAgent instance."""
    return ReleaseGaterAgent()


@pytest.mark.asyncio
async def test_go_decision_when_no_blockers(gater: ReleaseGaterAgent) -> None:
    """Release should be GO when there are no blocking issues."""
    decision = await gater.evaluate(
        findings=[],
        sast_findings=[],
        metadata={
            "test_coverage": 85.0,
            "sast_passed": True,
            "required_approvals": 2,
            "approvals_received": 2,
        },
        errors=[],
    )
    assert decision["decision"] == "GO"
    assert decision["status"] == "APPROVED"
    assert len(decision["blockers"]) == 0


@pytest.mark.asyncio
async def test_no_go_on_critical_finding(gater: ReleaseGaterAgent) -> None:
    """Release should be NO-GO when there are CRITICAL code review findings."""
    findings = [
        {
            "id": "abc123",
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "owasp_category": "A03:2021-Injection",
            "cwe_id": "CWE-89",
            "line_number": 42,
        }
    ]
    decision = await gater.evaluate(
        findings=findings,
        sast_findings=[],
        metadata={
            "test_coverage": 85.0,
            "sast_passed": True,
            "required_approvals": 1,
            "approvals_received": 1,
        },
        errors=[],
    )
    assert decision["decision"] == "NO-GO"
    assert decision["status"] == "BLOCKED"
    assert len(decision["blockers"]) > 0
    assert any("SQL Injection" in b or "CRITICAL" in b for b in decision["blockers"])


@pytest.mark.asyncio
async def test_no_go_on_insufficient_test_coverage(gater: ReleaseGaterAgent) -> None:
    """Release should be NO-GO when test coverage is below 70%."""
    decision = await gater.evaluate(
        findings=[],
        sast_findings=[],
        metadata={
            "test_coverage": 60.0,
            "sast_passed": True,
            "required_approvals": 2,
            "approvals_received": 2,
        },
        errors=[],
    )
    assert decision["decision"] == "NO-GO"
    assert any("coverage" in b.lower() or "60" in b for b in decision["blockers"])


@pytest.mark.asyncio
async def test_no_go_on_insufficient_approvals(gater: ReleaseGaterAgent) -> None:
    """Release should be NO-GO when required approvals have not been received."""
    decision = await gater.evaluate(
        findings=[],
        sast_findings=[],
        metadata={
            "test_coverage": 90.0,
            "sast_passed": True,
            "required_approvals": 2,
            "approvals_received": 1,
        },
        errors=[],
    )
    assert decision["decision"] == "NO-GO"
    assert any("approval" in b.lower() for b in decision["blockers"])


@pytest.mark.asyncio
async def test_no_go_when_sast_failed(gater: ReleaseGaterAgent) -> None:
    """Release should be NO-GO when SAST gate explicitly failed."""
    decision = await gater.evaluate(
        findings=[],
        sast_findings=[],
        metadata={
            "test_coverage": 85.0,
            "sast_passed": False,
            "required_approvals": 2,
            "approvals_received": 2,
        },
        errors=[],
    )
    assert decision["decision"] == "NO-GO"
    assert any("sast" in b.lower() for b in decision["blockers"])


@pytest.mark.asyncio
async def test_warning_on_borderline_coverage(gater: ReleaseGaterAgent) -> None:
    """Coverage between 70-80% should trigger a warning, not a blocker."""
    decision = await gater.evaluate(
        findings=[],
        sast_findings=[],
        metadata={
            "test_coverage": 75.0,
            "sast_passed": True,
            "required_approvals": 2,
            "approvals_received": 2,
        },
        errors=[],
    )
    assert decision["decision"] == "GO"
    assert len(decision["blockers"]) == 0
    assert any("coverage" in w.lower() or "75" in w for w in decision["warnings"])


@pytest.mark.asyncio
async def test_evidence_populated(gater: ReleaseGaterAgent) -> None:
    """Evidence dict should contain code_review, sast, test_coverage, and approvals."""
    decision = await gater.evaluate(
        findings=[{"severity": "LOW", "title": "Minor issue"}],
        sast_findings=[],
        metadata={
            "test_coverage": 82.0,
            "sast_passed": True,
            "required_approvals": 1,
            "approvals_received": 1,
        },
        errors=[],
    )
    evidence = decision["evidence"]
    assert "code_review" in evidence
    assert "sast" in evidence
    assert "approvals" in evidence
    assert evidence["code_review"]["total_findings"] == 1


@pytest.mark.asyncio
async def test_no_go_on_critical_sast_finding(gater: ReleaseGaterAgent) -> None:
    """CRITICAL SAST findings should block the release."""
    sast_findings = [
        {
            "id": "sast-001",
            "rule_id": "python.lang.security.audit.eval-detected",
            "title": "Eval Detected",
            "severity": "CRITICAL",
            "cwe_id": "CWE-94",
            "file_path": "app.py",
            "line_start": 10,
        }
    ]
    decision = await gater.evaluate(
        findings=[],
        sast_findings=sast_findings,
        metadata={
            "test_coverage": 85.0,
            "sast_passed": True,
            "required_approvals": 1,
            "approvals_received": 1,
        },
        errors=[],
    )
    assert decision["decision"] == "NO-GO"
    assert any("SAST" in b or "Eval" in b for b in decision["blockers"])


@pytest.mark.asyncio
async def test_errors_appear_as_warnings(gater: ReleaseGaterAgent) -> None:
    """Pipeline agent errors should appear as warnings in the decision."""
    decision = await gater.evaluate(
        findings=[],
        sast_findings=[],
        metadata={
            "test_coverage": 85.0,
            "sast_passed": True,
            "required_approvals": 1,
            "approvals_received": 1,
        },
        errors=["sast-analyst: timeout after 120s"],
    )
    assert decision["decision"] == "GO"  # errors alone don't block
    assert any("error" in w.lower() or "timeout" in w.lower() for w in decision["warnings"])
