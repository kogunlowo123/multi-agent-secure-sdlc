"""JWT authentication middleware."""
from __future__ import annotations

import jwt
import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)

EXEMPT_PATHS = frozenset(
    {
        "/api/v1/health",
        "/api/v1/readiness",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
    }
)


class AuthMiddleware(BaseHTTPMiddleware):
    """JWT authentication middleware for protected endpoints."""

    async def dispatch(self, request: Request, call_next: any) -> Response:
        """Validate JWT Bearer token on non-exempt endpoints."""
        path = request.url.path

        if path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        from api.config import get_settings

        settings = get_settings()

        # In test/dev environments, skip auth and inject synthetic identity
        if settings.app_env in ("test", "development"):
            request.state.tenant_id = "dev-tenant"
            request.state.user_id = "dev-user"
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header. Expected: Bearer <token>"},
            )

        token = auth_header.removeprefix("Bearer ").strip()
        try:
            payload = jwt.decode(
                token,
                settings.secret_key,
                algorithms=[settings.jwt_algorithm],
                options={"verify_exp": True},
            )
            request.state.tenant_id = payload.get("tenant_id", "unknown")
            request.state.user_id = payload.get("sub", "unknown")
        except jwt.ExpiredSignatureError:
            return JSONResponse(
                status_code=401, content={"detail": "Token has expired"}
            )
        except jwt.InvalidTokenError as exc:
            logger.warning("invalid_jwt_token", error=str(exc), path=path)
            return JSONResponse(
                status_code=401, content={"detail": "Invalid authentication token"}
            )

        return await call_next(request)
