"""
OpenTelemetry distributed tracing setup.
Provides standardized tracing across all Cobalto services.
"""

from functools import lru_cache
from typing import Optional
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION, DEPLOYMENT_ENVIRONMENT
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.propagate import set_global_textmap
from .config import get_settings
from .logging import get_logger

logger = get_logger(__name__)


def setup_tracing(
    service_name: str,
    service_version: str = "0.1.0",
    otel_endpoint: Optional[str] = None,
    sample_rate: float = 0.1,
) -> trace.Tracer:
    """Initialize OpenTelemetry tracing."""
    settings = get_settings()

    endpoint = otel_endpoint or settings.otel_endpoint
    name = service_name or settings.otel_service_name

    # Create resource
    resource = Resource.create({
        SERVICE_NAME: name,
        SERVICE_VERSION: service_version,
        DEPLOYMENT_ENVIRONMENT: settings.app_env,
    })

    # Create tracer provider
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    # Configure exporter
    if settings.is_production or settings.is_staging:
        exporter = OTLPSpanExporter(
            endpoint=endpoint,
            insecure=True,
        )
    else:
        exporter = ConsoleSpanExporter()

    # Add span processor
    provider.add_span_processor(BatchSpanProcessor(exporter))

    # Set global propagator
    set_global_textmap(TraceContextTextMapPropagator())

    # Auto-instrument libraries
    _setup_auto_instrumentation()

    logger.info("tracing_initialized", service=name, endpoint=endpoint, sample_rate=sample_rate)

    return trace.get_tracer(name, service_version)


def _setup_auto_instrumentation() -> None:
    """Configure automatic instrumentation for common libraries."""
    try:
        FastAPIInstrumentor.instrument()
        HTTPXClientInstrumentor.instrument()
        RedisInstrumentor.instrument()
        Psycopg2Instrumentor.instrument()
        RequestsInstrumentor.instrument()
        AioHttpClientInstrumentor.instrument()
    except Exception as e:
        logger.warning("auto_instrumentation_failed", error=str(e))


def get_tracer(name: str) -> trace.Tracer:
    """Get a tracer instance."""
    return trace.get_tracer(name)


class TracedOperation:
    """Context manager for creating traced operations."""

    def __init__(
        self,
        tracer: trace.Tracer,
        operation_name: str,
        attributes: Optional[dict] = None,
        kind: trace.SpanKind = trace.SpanKind.INTERNAL,
    ):
        self.tracer = tracer
        self.operation_name = operation_name
        self.attributes = attributes or {}
        self.kind = kind
        self.span: Optional[trace.Span] = None

    def __enter__(self) -> trace.Span:
        self.span = self.tracer.start_span(
            self.operation_name,
            kind=self.kind,
            attributes=self.attributes,
        )
        self.span.__enter__()
        return self.span

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.span:
            if exc_type:
                self.span.record_exception(exc_val)
                self.span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc_val)))
            else:
                self.span.set_status(trace.Status(trace.StatusCode.OK))
            self.span.__exit__(exc_type, exc_val, exc_tb)


def trace_function(tracer: trace.Tracer, operation_name: Optional[str] = None, kind: trace.SpanKind = trace.SpanKind.INTERNAL):
    """Decorator to trace a function."""
    import functools

    def decorator(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            name = operation_name or f"{func.__module__}.{func.__qualname__}"
            with TracedOperation(tracer, name, kind=kind) as span:
                if span:
                    span.set_attribute("function.name", func.__name__)
                    span.set_attribute("function.module", func.__module__)
                return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            name = operation_name or f"{func.__module__}.{func.__qualname__}"
            with TracedOperation(tracer, name, kind=kind) as span:
                if span:
                    span.set_attribute("function.name", func.__name__)
                    span.set_attribute("function.module", func.__module__)
                return func(*args, **kwargs)

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def inject_context(carrier: dict) -> None:
    """Inject trace context into carrier for propagation."""
    trace.get_tracer_provider().get_tracer("").get_span_context(carrier)


def extract_context(carrier: dict) -> trace.SpanContext:
    """Extract trace context from carrier."""
    return TraceContextTextMapPropagator().extract(carrier)