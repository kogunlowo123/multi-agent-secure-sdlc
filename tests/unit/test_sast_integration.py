"""Unit tests for SAST integration using known-vulnerable Python code snippets.

These tests verify that the SASTScanTool correctly identifies security
vulnerabilities using semgrep or the built-in heuristic fallback.
"""
from __future__ import annotations

import pytest

from agent_runtime.tools.sast_scan import SASTScanTool


@pytest.fixture
def sast_tool() -> SASTScanTool:
    """Provide a SASTScanTool instance."""
    return SASTScanTool(timeout=30)


@pytest.mark.asyncio
async def test_detects_command_injection_shell_true(sast_tool: SASTScanTool) -> None:
    """SAST should detect command injection when shell=True is used with subprocess."""
    code = """
import subprocess

def run_user_command(user_input: str):
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout.decode()
"""
    findings = await sast_tool.scan(code=code, language="python")

    assert len(findings) > 0, "Expected at least one finding for shell=True"

    severities = {f.severity for f in findings}
    assert "HIGH" in severities or "CRITICAL" in severities, (
        f"Expected HIGH or CRITICAL severity, got: {severities}"
    )

    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    assert any(cwe in cwe_ids for cwe in {"CWE-78", "CWE-94"}), (
        f"Expected CWE-78 or CWE-94 mapping, got: {cwe_ids}"
    )


@pytest.mark.asyncio
async def test_detects_eval_injection(sast_tool: SASTScanTool) -> None:
    """SAST should detect code injection via eval()."""
    code = """
def calculate(expression: str):
    return eval(expression)
"""
    findings = await sast_tool.scan(code=code, language="python")

    assert len(findings) > 0, "Expected at least one finding for eval()"

    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    assert "CWE-94" in cwe_ids, f"Expected CWE-94 for eval(), got: {cwe_ids}"


@pytest.mark.asyncio
async def test_detects_pickle_deserialization(sast_tool: SASTScanTool) -> None:
    """SAST should detect insecure deserialization via pickle.loads."""
    code = """
import pickle
import base64

def deserialize_session(data: str):
    raw = base64.b64decode(data)
    return pickle.loads(raw)
"""
    findings = await sast_tool.scan(code=code, language="python")

    assert len(findings) > 0, "Expected at least one finding for pickle.loads"

    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    assert "CWE-502" in cwe_ids, f"Expected CWE-502 for pickle.loads(), got: {cwe_ids}"

    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities or "HIGH" in severities, (
        f"pickle.loads should be CRITICAL or HIGH, got: {severities}"
    )


@pytest.mark.asyncio
async def test_detects_md5_weak_hash(sast_tool: SASTScanTool) -> None:
    """SAST should detect use of cryptographically weak MD5 hash."""
    code = """
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
"""
    findings = await sast_tool.scan(code=code, language="python")

    assert len(findings) > 0, "Expected at least one finding for MD5 usage"

    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    assert "CWE-327" in cwe_ids or "CWE-328" in cwe_ids, (
        f"Expected CWE-327 or CWE-328 for weak hash, got: {cwe_ids}"
    )


@pytest.mark.asyncio
async def test_no_findings_for_safe_code(sast_tool: SASTScanTool) -> None:
    """SAST should produce no HIGH/CRITICAL findings for secure code patterns."""
    safe_code = """
import hashlib
import secrets
import subprocess

def create_secure_token() -> str:
    return secrets.token_urlsafe(32)

def hash_data(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def run_safe_command(filename: str) -> str:
    # Pass command as list, no shell=True
    result = subprocess.run(["ls", "-la", filename], capture_output=True, text=True)
    return result.stdout
"""
    findings = await sast_tool.scan(code=safe_code, language="python")

    critical_high = [
        f for f in findings if f.severity in ("CRITICAL", "HIGH")
    ]
    assert len(critical_high) == 0, (
        f"Expected no CRITICAL/HIGH findings for safe code, got: "
        f"{[(f.title, f.severity, f.cwe_id) for f in critical_high]}"
    )


@pytest.mark.asyncio
async def test_sast_returns_sast_finding_objects(sast_tool: SASTScanTool) -> None:
    """SAST scan results should be valid SASTFinding Pydantic models."""
    from api.schemas.vulnerability import SASTFinding

    code = "import subprocess\nsubprocess.run(user_cmd, shell=True)"
    findings = await sast_tool.scan(code=code, language="python")

    for f in findings:
        assert isinstance(f, SASTFinding), f"Expected SASTFinding, got {type(f)}"
        assert f.id, "Finding must have a non-empty id"
        assert f.rule_id, "Finding must have a rule_id"
        assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), (
            f"Invalid severity: {f.severity}"
        )
        assert f.line_start >= 0, f"line_start should be >= 0, got {f.line_start}"


@pytest.mark.asyncio
async def test_detects_os_system_injection(sast_tool: SASTScanTool) -> None:
    """SAST should detect command injection via os.system()."""
    code = """
import os

def execute(cmd: str):
    os.system(cmd)
"""
    findings = await sast_tool.scan(code=code, language="python")

    assert len(findings) > 0, "Expected finding for os.system()"

    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    assert "CWE-78" in cwe_ids, f"Expected CWE-78 for os.system(), got: {cwe_ids}"


@pytest.mark.asyncio
async def test_multiple_vulnerabilities_detected(sast_tool: SASTScanTool) -> None:
    """SAST should detect multiple vulnerabilities in a single code snippet."""
    code = """
import subprocess
import hashlib
import pickle

def process(user_cmd: str, data: bytes, password: str):
    # Multiple security issues
    result = subprocess.run(user_cmd, shell=True)
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    obj = pickle.loads(data)
    return result, pwd_hash, obj
"""
    findings = await sast_tool.scan(code=code, language="python")

    assert len(findings) >= 2, (
        f"Expected at least 2 findings for code with multiple vulnerabilities, got {len(findings)}"
    )

    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    # Should detect at least some of the known CWEs
    expected_cwes = {"CWE-78", "CWE-327", "CWE-502"}
    detected = expected_cwes.intersection(cwe_ids)
    assert len(detected) >= 2, (
        f"Expected at least 2 of {expected_cwes} to be detected, got: {cwe_ids}"
    )
