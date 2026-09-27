"""Per-client rate limiting middleware."""
from __future__ import annotations

import time
from collections import defaultdict

import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)

# Simple in-memory rate limiter (sliding window per IP).
# Replace with Redis-backed implementation for multi-instance deployments.
_request_timestamps: dict[str, list[float]] = defaultdict(list)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter per client IP address."""

    async def dispatch(self, request: Request, call_next: any) -> Response:
        """Enforce per-minute rate limit per client IP."""
        from api.config import get_settings

        settings = get_settings()
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window_start = now - 60.0

        timestamps = _request_timestamps[client_ip]
        # Evict expired timestamps
        timestamps[:] = [t for t in timestamps if t > window_start]

        if len(timestamps) >= settings.rate_limit_per_minute:
            logger.warning(
                "rate_limit_exceeded",
                client_ip=client_ip,
                count=len(timestamps),
                limit=settings.rate_limit_per_minute,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit of {settings.rate_limit_per_minute} requests/minute exceeded. Retry after 60 seconds."
                },
                headers={"Retry-After": "60", "X-RateLimit-Limit": str(settings.rate_limit_per_minute)},
            )

        timestamps.append(now)
        return await call_next(request)
