"""Integration tests for the API review flow endpoints."""
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def app():
    """Return the FastAPI application."""
    from api.main import create_app
    return create_app()


@pytest.fixture
async def client(app):
    """Provide an async HTTP test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    """Health endpoint should return 200 with healthy status."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "multi-agent-secure-sdlc"
    assert "version" in data
    assert "uptime_seconds" in data


@pytest.mark.asyncio
async def test_readiness_endpoint(client: AsyncClient) -> None:
    """Readiness endpoint should return 200."""
    response = await client.get("/api/v1/readiness")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "checks" in data


@pytest.mark.asyncio
async def test_code_review_endpoint_returns_result(client: AsyncClient) -> None:
    """Code review endpoint should return a CodeReviewResult."""
    payload = {
        "code_diff": "import subprocess\nsubprocess.run(user_cmd, shell=True)",
        "language": "python",
        "repository": "test-org/test-repo",
        "commit_sha": "abc123def456",
    }
    response = await client.post("/api/v1/code/review", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "review_id" in data
    assert "findings" in data
    assert "severity_distribution" in data
    assert "owasp_coverage" in data
    assert "reviewed_at" in data
    assert isinstance(data["findings"], list)


@pytest.mark.asyncio
async def test_code_review_detects_vulnerability(client: AsyncClient) -> None:
    """Code review endpoint should detect shell=True vulnerability."""
    payload = {
        "code_diff": "import subprocess\nsubprocess.run(user_cmd, shell=True)",
        "language": "python",
    }
    response = await client.post("/api/v1/code/review", json=payload)
    assert response.status_code == 200

    data = response.json()
    # Should find at least one security issue
    assert len(data["findings"]) > 0

    severities = {f["severity"] for f in data["findings"]}
    assert severities.intersection({"CRITICAL", "HIGH"}), (
        f"Expected HIGH or CRITICAL finding, got severities: {severities}"
    )


@pytest.mark.asyncio
async def test_sast_scan_endpoint(client: AsyncClient) -> None:
    """SAST scan endpoint should return a SASTScanResult."""
    payload = {
        "code": "import subprocess\nsubprocess.run(cmd, shell=True)",
        "language": "python",
        "filename": "app.py",
    }
    response = await client.post("/api/v1/sast/scan", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "scan_id" in data
    assert "findings" in data
    assert "total_findings" in data
    assert "severity_breakdown" in data
    assert "scanned_at" in data
    assert isinstance(data["findings"], list)
    assert data["total_findings"] == len(data["findings"])


@pytest.mark.asyncio
async def test_release_gate_endpoint_go_decision(client: AsyncClient) -> None:
    """Release gate should return GO for a clean release request."""
    payload = {
        "release_id": "test-release-001",
        "repository": "test-org/test-repo",
        "commit_sha": "abc123def456",
        "test_coverage": 90.0,
        "sast_passed": True,
        "required_approvals": 2,
        "approvals_received": 2,
    }
    response = await client.post("/api/v1/release/gate", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["release_id"] == "test-release-001"
    assert "decision" in data
    assert data["decision"] in ("GO", "NO-GO")
    assert "blockers" in data
    assert "evidence" in data
    assert "evaluated_at" in data


@pytest.mark.asyncio
async def test_release_gate_blocked_on_low_coverage(client: AsyncClient) -> None:
    """Release gate should return NO-GO when test coverage is below threshold."""
    payload = {
        "release_id": "test-release-002",
        "repository": "test-org/test-repo",
        "commit_sha": "def456abc789",
        "test_coverage": 50.0,
        "sast_passed": True,
        "required_approvals": 1,
        "approvals_received": 1,
    }
    response = await client.post("/api/v1/release/gate", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["decision"] == "NO-GO"
    assert len(data["blockers"]) > 0
    assert any("coverage" in b.lower() for b in data["blockers"])


@pytest.mark.asyncio
async def test_release_status_not_found(client: AsyncClient) -> None:
    """Getting status for unknown release ID should return 404."""
    response = await client.get("/api/v1/release/nonexistent-release-id/status")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_release_status_after_gate(client: AsyncClient) -> None:
    """Getting status after a gate evaluation should return the stored decision."""
    payload = {
        "release_id": "test-release-status-003",
        "repository": "test-org/test-repo",
        "commit_sha": "xyz789",
        "test_coverage": 85.0,
        "sast_passed": True,
        "required_approvals": 1,
        "approvals_received": 1,
    }
    # First, gate the release
    gate_response = await client.post("/api/v1/release/gate", json=payload)
    assert gate_response.status_code == 200

    # Then get the status
    status_response = await client.get("/api/v1/release/test-release-status-003/status")
    assert status_response.status_code == 200
    data = status_response.json()
    assert data["release_id"] == "test-release-status-003"


@pytest.mark.asyncio
async def test_openapi_schema_available(client: AsyncClient) -> None:
    """OpenAPI schema should be accessible."""
    response = await client.get("/api/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "Multi-Agent Secure SDLC API"


@pytest.mark.asyncio
async def test_code_review_validates_request_body(client: AsyncClient) -> None:
    """Code review endpoint should return 422 for missing required fields."""
    response = await client.post("/api/v1/code/review", json={"language": "python"})
    assert response.status_code == 422  # Pydantic validation error
