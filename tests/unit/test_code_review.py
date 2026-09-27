"""Unit tests for the code reviewer agent."""
from __future__ import annotations

import pytest

from agent_runtime.agents.code_reviewer import CodeReviewerAgent


@pytest.fixture
def agent() -> CodeReviewerAgent:
    """Provide a CodeReviewerAgent instance."""
    return CodeReviewerAgent()


@pytest.mark.asyncio
async def test_heuristic_detects_shell_true(agent: CodeReviewerAgent) -> None:
    """Heuristic review should detect shell=True command injection."""
    code = "import subprocess\nsubprocess.run(user_input, shell=True)"
    findings = agent._heuristic_review(code, "python")

    assert len(findings) > 0
    titles = [f["title"] for f in findings]
    assert any("injection" in t.lower() or "shell" in t.lower() for t in titles), (
        f"Expected injection/shell finding, got titles: {titles}"
    )


@pytest.mark.asyncio
async def test_heuristic_detects_eval(agent: CodeReviewerAgent) -> None:
    """Heuristic review should detect eval() code injection."""
    code = "result = eval(user_expression)"
    findings = agent._heuristic_review(code, "python")

    assert len(findings) > 0
    cwe_ids = [f.get("cwe_id") for f in findings]
    assert "CWE-94" in cwe_ids, f"Expected CWE-94, got: {cwe_ids}"


@pytest.mark.asyncio
async def test_heuristic_detects_pickle(agent: CodeReviewerAgent) -> None:
    """Heuristic review should detect insecure pickle deserialization."""
    code = "import pickle\nobj = pickle.loads(user_data)"
    findings = agent._heuristic_review(code, "python")

    assert len(findings) > 0
    severities = [f.get("severity") for f in findings]
    assert "CRITICAL" in severities, f"pickle.loads should be CRITICAL, got: {severities}"


@pytest.mark.asyncio
async def test_heuristic_detects_md5(agent: CodeReviewerAgent) -> None:
    """Heuristic review should detect weak MD5 hash usage."""
    code = "import hashlib\nhash = hashlib.md5(password.encode()).hexdigest()"
    findings = agent._heuristic_review(code, "python")

    assert len(findings) > 0
    cwe_ids = [f.get("cwe_id") for f in findings]
    assert "CWE-327" in cwe_ids, f"Expected CWE-327 for MD5, got: {cwe_ids}"


@pytest.mark.asyncio
async def test_safe_code_no_critical_findings(agent: CodeReviewerAgent) -> None:
    """Safe code should produce no CRITICAL findings."""
    safe_code = """
import secrets
import hashlib

def secure_function(data: str) -> str:
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(data.encode()).hexdigest()
    return f"{token}:{digest}"
"""
    findings = agent._heuristic_review(safe_code, "python")
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    assert len(critical) == 0, f"Expected no CRITICAL findings for safe code, got: {critical}"


@pytest.mark.asyncio
async def test_review_falls_back_to_heuristic_without_llm(agent: CodeReviewerAgent) -> None:
    """Review method should fall back to heuristic when Azure OpenAI is not configured."""
    code = "subprocess.run(cmd, shell=True)"
    # With no Azure OpenAI configured, should use heuristic
    findings = await agent.review(code_diff=code, language="python")
    assert isinstance(findings, list)
    # Heuristic should detect shell=True
    assert len(findings) > 0


@pytest.mark.asyncio
async def test_finding_has_required_fields(agent: CodeReviewerAgent) -> None:
    """All heuristic findings should have the required fields."""
    code = "eval(user_input)"
    findings = agent._heuristic_review(code, "python")

    required_fields = {"id", "title", "description", "severity", "recommendation"}
    for finding in findings:
        missing = required_fields - set(finding.keys())
        assert not missing, f"Finding missing required fields: {missing}"
        assert finding["id"], "Finding id must not be empty"
        assert finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, (
            f"Invalid severity: {finding['severity']}"
        )


@pytest.mark.asyncio
async def test_multiple_issues_detected(agent: CodeReviewerAgent) -> None:
    """Multiple security issues in one code snippet should all be detected."""
    code = """
import subprocess
import hashlib
import pickle

result = subprocess.run(cmd, shell=True)
h = hashlib.md5(data).hexdigest()
obj = pickle.loads(raw)
"""
    findings = agent._heuristic_review(code, "python")
    assert len(findings) >= 2, (
        f"Expected at least 2 findings for code with 3 vulnerabilities, got {len(findings)}"
    )
