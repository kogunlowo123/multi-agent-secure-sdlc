"""Security tests: verify that the SAST and code review pipeline detects known vulnerabilities."""
from __future__ import annotations

import pytest

from agent_runtime.tools.sast_scan import SASTScanTool
from agent_runtime.agents.code_reviewer import CodeReviewerAgent


INJECTION_SAMPLES = [
    # (description, code, expected_cwe)
    (
        "SQL injection via f-string",
        'query = f"SELECT * FROM users WHERE name=\'{user_input}\'"',
        None,  # May not be detected by heuristic; checked by presence of finding
    ),
    (
        "Command injection via shell=True",
        "import subprocess\nsubprocess.run(user_input, shell=True)",
        "CWE-78",
    ),
    (
        "Code injection via eval()",
        "result = eval(user_expression)",
        "CWE-94",
    ),
    (
        "Code injection via exec()",
        "exec(compile(user_code, '<string>', 'exec'))",
        None,
    ),
]

CRYPTO_SAMPLES = [
    (
        "MD5 password hashing",
        "import hashlib\nhash = hashlib.md5(pw.encode()).hexdigest()",
        "CWE-327",
    ),
    (
        "SHA1 usage",
        "import hashlib\nresult = hashlib.sha1(data).hexdigest()",
        "CWE-328",
    ),
]

DESERIALIZATION_SAMPLES = [
    (
        "Pickle deserialization",
        "import pickle\nobj = pickle.loads(user_data)",
        "CWE-502",
    ),
]


@pytest.fixture
def sast_tool() -> SASTScanTool:
    return SASTScanTool(timeout=30)


@pytest.fixture
def code_reviewer() -> CodeReviewerAgent:
    return CodeReviewerAgent()


@pytest.mark.asyncio
@pytest.mark.parametrize("description,code,expected_cwe", INJECTION_SAMPLES)
async def test_sast_detects_injection(
    sast_tool: SASTScanTool,
    description: str,
    code: str,
    expected_cwe: str | None,
) -> None:
    """SAST should detect injection vulnerabilities."""
    findings = await sast_tool.scan(code=code, language="python")
    assert len(findings) > 0, (
        f"Expected SAST finding for '{description}' but got none"
    )
    if expected_cwe:
        cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
        assert expected_cwe in cwe_ids, (
            f"Expected {expected_cwe} for '{description}', got: {cwe_ids}"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("description,code,expected_cwe", CRYPTO_SAMPLES)
async def test_sast_detects_weak_crypto(
    sast_tool: SASTScanTool,
    description: str,
    code: str,
    expected_cwe: str,
) -> None:
    """SAST should detect weak cryptographic usage."""
    findings = await sast_tool.scan(code=code, language="python")
    assert len(findings) > 0, (
        f"Expected SAST finding for '{description}' but got none"
    )
    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    assert expected_cwe in cwe_ids, (
        f"Expected {expected_cwe} for '{description}', got: {cwe_ids}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("description,code,expected_cwe", DESERIALIZATION_SAMPLES)
async def test_sast_detects_deserialization(
    sast_tool: SASTScanTool,
    description: str,
    code: str,
    expected_cwe: str,
) -> None:
    """SAST should detect insecure deserialization."""
    findings = await sast_tool.scan(code=code, language="python")
    assert len(findings) > 0, (
        f"Expected SAST finding for '{description}' but got none"
    )
    cwe_ids = {f.cwe_id for f in findings if f.cwe_id}
    assert expected_cwe in cwe_ids, (
        f"Expected {expected_cwe} for '{description}', got: {cwe_ids}"
    )


@pytest.mark.asyncio
async def test_code_reviewer_detects_shell_injection(code_reviewer: CodeReviewerAgent) -> None:
    """Code reviewer should flag shell=True as HIGH or CRITICAL."""
    code = "import subprocess\nresult = subprocess.check_output(cmd, shell=True)"
    findings = code_reviewer._heuristic_review(code, "python")

    high_critical = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    assert len(high_critical) > 0, "Expected HIGH/CRITICAL finding for shell=True"


@pytest.mark.asyncio
async def test_owasp_categories_mapped(sast_tool: SASTScanTool) -> None:
    """SAST findings should have OWASP categories mapped from CWE."""
    code = "import subprocess\nsubprocess.run(user_cmd, shell=True)"
    findings = await sast_tool.scan(code=code, language="python")

    findings_with_owasp = [f for f in findings if f.owasp_category]
    assert len(findings_with_owasp) > 0, (
        "Expected at least one finding with OWASP category mapping"
    )
    # shell=True should map to A03 injection
    owasp_cats = {f.owasp_category for f in findings_with_owasp}
    assert any("Injection" in cat for cat in owasp_cats if cat), (
        f"Expected injection OWASP category, got: {owasp_cats}"
    )


@pytest.mark.asyncio
async def test_fix_guidance_provided(sast_tool: SASTScanTool) -> None:
    """SAST findings with known CWEs should include fix guidance."""
    code = "import subprocess\nsubprocess.run(cmd, shell=True)"
    findings = await sast_tool.scan(code=code, language="python")

    findings_with_guidance = [f for f in findings if f.fix_guidance]
    assert len(findings_with_guidance) > 0, (
        "Expected at least one finding with fix guidance"
    )


@pytest.mark.asyncio
async def test_no_false_positives_on_safe_subprocess(sast_tool: SASTScanTool) -> None:
    """Safe subprocess usage (no shell=True) should not trigger injection finding."""
    safe_code = """
import subprocess

def list_files(directory: str) -> str:
    result = subprocess.run(
        ["ls", "-la", directory],
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout
"""
    findings = await sast_tool.scan(code=safe_code, language="python")

    shell_injection = [
        f for f in findings
        if f.cwe_id == "CWE-78" and f.severity in ("CRITICAL", "HIGH")
    ]
    assert len(shell_injection) == 0, (
        f"False positive: shell injection detected in safe code: {shell_injection}"
    )
