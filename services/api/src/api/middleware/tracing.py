"""Distributed tracing middleware."""
from __future__ import annotations

import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)


class TracingMiddleware(BaseHTTPMiddleware):
    """Injects trace and request IDs into request context and response headers."""

    async def dispatch(self, request: Request, call_next: any) -> Response:
        """Propagate or generate trace context."""
        trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
        request_id = str(uuid.uuid4())

        request.state.trace_id = trace_id
        request.state.request_id = request_id

        with structlog.contextvars.bound_contextvars(
            trace_id=trace_id,
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        ):
            response = await call_next(request)

        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Request-ID"] = request_id
        return response
