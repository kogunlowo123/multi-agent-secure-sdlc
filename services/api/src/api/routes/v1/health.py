"""Health and readiness check endpoints."""
import time
from typing import Any

import structlog
from fastapi import APIRouter

router = APIRouter()
logger = structlog.get_logger(__name__)
_start_time = time.time()


@router.get("/health", summary="Health check")
async def health() -> dict[str, Any]:
    """Basic liveness health check."""
    return {
        "status": "healthy",
        "service": "multi-agent-secure-sdlc",
        "version": "0.1.0",
        "uptime_seconds": round(time.time() - _start_time, 2),
    }


@router.get("/readiness", summary="Readiness probe")
async def readiness() -> dict[str, Any]:
    """Readiness probe — verifies all required dependencies are reachable."""
    checks: dict[str, str] = {}

    try:
        from api.config import get_settings

        settings = get_settings()
        import psycopg2

        conn = psycopg2.connect(settings.database_url, connect_timeout=3)
        conn.close()
        checks["postgres"] = "ok"
    except ImportError:
        checks["postgres"] = "skip (psycopg2 not installed)"
    except Exception as exc:
        logger.warning("readiness_postgres_fail", error=str(exc))
        checks["postgres"] = f"fail: {exc}"

    overall = "ready" if all(v.startswith("ok") or v.startswith("skip") for v in checks.values()) else "not_ready"
    return {"status": overall, "checks": checks}
