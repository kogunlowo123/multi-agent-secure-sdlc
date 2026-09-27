"""Multi-Agent Secure SDLC API Service entry point."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

logger = structlog.get_logger(__name__)


def configure_telemetry(app_name: str, otlp_endpoint: str) -> None:
    """Configure OpenTelemetry tracing."""
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({"service.name": app_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        logger.info("telemetry_configured", service=app_name, endpoint=otlp_endpoint)
    except Exception as exc:
        logger.warning("telemetry_configuration_failed", error=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    from api.config import get_settings

    settings = get_settings()

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
            if settings.app_env == "development"
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level.upper())
        ),
    )

    logger.info(
        "starting_application",
        service="secure-sdlc-api",
        env=settings.app_env,
        version="0.1.0",
    )

    configure_telemetry(settings.otel_service_name, settings.otel_exporter_otlp_endpoint)

    yield

    logger.info("shutting_down_application", service="secure-sdlc-api")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    from api.middleware.auth import AuthMiddleware
    from api.middleware.ratelimit import RateLimitMiddleware
    from api.middleware.tenant import TenantMiddleware
    from api.middleware.tracing import TracingMiddleware
    from api.routes.v1 import code, health, release, sast

    app = FastAPI(
        title="Multi-Agent Secure SDLC API",
        description=(
            "Enterprise AI platform for security-aware software delivery. "
            "AI agents perform code review, SAST analysis, and release gating."
        ),
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(TracingMiddleware)
    app.add_middleware(TenantMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuthMiddleware)

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(code.router, prefix="/api/v1", tags=["code-review"])
    app.include_router(release.router, prefix="/api/v1", tags=["release"])
    app.include_router(sast.router, prefix="/api/v1", tags=["sast"])

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        pass

    return app


app = create_app()
