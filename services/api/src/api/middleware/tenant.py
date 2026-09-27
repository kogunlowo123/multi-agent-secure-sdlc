"""Tenant context middleware."""
from __future__ import annotations

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)


class TenantMiddleware(BaseHTTPMiddleware):
    """Extracts and propagates tenant context from request headers."""

    async def dispatch(self, request: Request, call_next: any) -> Response:
        """Extract tenant ID from X-Tenant-ID header and set on request state."""
        tenant_id = request.headers.get("X-Tenant-ID", "default")
        if not hasattr(request.state, "tenant_id") or not request.state.tenant_id:
            request.state.tenant_id = tenant_id
        return await call_next(request)
