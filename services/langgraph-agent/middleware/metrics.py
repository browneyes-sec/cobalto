"""
Metrics Registry — Prometheus instrumentation for the LangGraph agent service.

Exports the metrics that the ``agent-performance`` Grafana dashboard expects:

  - ``cobalto_agent_latency_seconds`` — Histogram of agent execution duration
  - ``cobalto_tool_calls_total`` — Counter of tool calls, labelled by tool + status
  - ``cobalto_tool_latency_seconds`` — Histogram of tool execution time
  - ``cobalto_agent_errors_total`` — Counter of agent errors
  - ``cobalto_agent_investigations_total`` — Counter of investigations started
  - ``cobalto_agent_operations_total`` — Counter of all agent operations
  - ``cobalto_llm_tokens_total`` — Counter of LLM tokens consumed (estimated)

Usage::

    from middleware.metrics import metrics

    # Record a tool call
    metrics.tool_call_duration("mitre_attack_search", 0.342, status="success")

    # Record an agent execution
    metrics.agent_execution("triage", 1.23)

    # Expose via FastAPI
    @app.get("/metrics")
    async def metrics_endpoint():
        return Response(
            content=metrics.generate(),
            media_type="text/plain",
        )
"""

from __future__ import annotations

import time
from functools import wraps
from typing import Any, Callable, Optional

from prometheus_client import (
    Counter,
    Histogram,
    generate_latest,
    REGISTRY,
    CONTENT_TYPE_LATEST,
)


class MetricsRegistry:
    """Central registry for all Prometheus metrics emitted by the agent service.

    Every metric name follows the ``cobalto_`` prefix convention expected
    by the Grafana dashboards provisioned in ``kubernetes/grafana/``.

    Parameters
    ----------
    namespace:
        Prefix for all metric names (default ``"cobalto"``).
    registry:
        Prometheus ``CollectorRegistry`` to use. Defaults to the global
        ``REGISTRY``. Pass a fresh ``CollectorRegistry()`` in tests to
        avoid ``Duplicated timeseries`` errors.
    """

    def __init__(
        self,
        namespace: str = "cobalto",
        registry: Any = None,
    ) -> None:
        from prometheus_client import CollectorRegistry
        self._namespace = namespace
        self._registry = registry if registry is not None else REGISTRY
        r = self._registry

        # ── Agent-level metrics ────────────────────────────────────
        self.agent_latency = Histogram(
            name=f"{namespace}_agent_latency_seconds",
            documentation="Agent execution duration in seconds",
            labelnames=["agent"],
            buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float("inf")),
            registry=r,
        )
        self.agent_investigations = Counter(
            name=f"{namespace}_agent_investigations_total",
            documentation="Total number of investigations started",
            labelnames=["agent"],
            registry=r,
        )
        self.agent_operations = Counter(
            name=f"{namespace}_agent_operations_total",
            documentation="Total number of agent operations (executions)",
            labelnames=["agent", "status"],
            registry=r,
        )
        self.agent_errors = Counter(
            name=f"{namespace}_agent_errors_total",
            documentation="Total number of agent errors",
            labelnames=["agent", "error_type"],
            registry=r,
        )

        # ── Tool-level metrics ─────────────────────────────────────
        self.tool_calls = Counter(
            name=f"{namespace}_tool_calls_total",
            documentation="Total number of tool calls",
            labelnames=["tool", "status"],
            registry=r,
        )
        self.tool_latency = Histogram(
            name=f"{namespace}_tool_latency_seconds",
            documentation="Tool execution duration in seconds",
            labelnames=["tool"],
            buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float("inf")),
            registry=r,
        )
        self.tool_errors = Counter(
            name=f"{namespace}_tool_errors_total",
            documentation="Total number of tool errors",
            labelnames=["tool", "error_type"],
            registry=r,
        )

        # ── LLM metrics ────────────────────────────────────────────
        self.llm_tokens = Counter(
            name=f"{namespace}_llm_tokens_total",
            documentation="Estimated total LLM tokens consumed",
            labelnames=["agent", "model"],
            registry=r,
        )

        # ── Alert ingestion metrics ────────────────────────────────
        self.alerts_received = Counter(
            name=f"{namespace}_alerts_received_total",
            documentation="Total number of alerts received via webhook",
            labelnames=["source", "severity"],
            registry=r,
        )

    # ── Recording helpers ───────────────────────────────────────────

    def agent_execution(
        self,
        agent_name: str,
        duration_seconds: float,
        status: str = "success",
    ) -> None:
        """Record an agent execution with its duration."""
        self.agent_latency.labels(agent=agent_name).observe(duration_seconds)
        self.agent_operations.labels(agent=agent_name, status=status).inc()

    def agent_investigation_started(self, agent_name: str = "system") -> None:
        """Record that a new investigation was started."""
        self.agent_investigations.labels(agent=agent_name).inc()

    def agent_error(self, agent_name: str, error_type: str = "exception") -> None:
        """Record an agent error."""
        self.agent_errors.labels(agent=agent_name, error_type=error_type).inc()

    def tool_call(
        self,
        tool_name: str,
        duration_seconds: float,
        status: str = "success",
    ) -> None:
        """Record a tool call with its duration and outcome."""
        self.tool_calls.labels(tool=tool_name, status=status).inc()
        self.tool_latency.labels(tool=tool_name).observe(duration_seconds)
        if status != "success":
            self.tool_errors.labels(tool=tool_name, error_type=status).inc()

    def tool_call_duration(
        self,
        tool_name: str,
        duration_seconds: float,
        status: str = "success",
    ) -> None:
        """Alias for ``tool_call`` for backwards compatibility."""
        self.tool_call(tool_name, duration_seconds, status)

    def llm_tokens_consumed(
        self,
        agent_name: str,
        tokens: int,
        model: str = "gpt-4",
    ) -> None:
        """Record estimated LLM token consumption."""
        self.llm_tokens.labels(agent=agent_name, model=model).inc(tokens)

    def alert_received(
        self,
        source: str = "wazuh",
        severity: str = "informational",
    ) -> None:
        """Record an alert received via webhook."""
        self.alerts_received.labels(source=source, severity=severity).inc()

    # ── Export ──────────────────────────────────────────────────────

    def generate(self) -> bytes:
        """Generate the Prometheus exposition format text.

        Returns bytes ready to serve as the HTTP response body for ``/metrics``.
        """
        return generate_latest(self._registry)

    @property
    def content_type(self) -> str:
        """The ``Content-Type`` header value for the metrics endpoint."""
        return CONTENT_TYPE_LATEST

    # ── Decorator for tool functions ────────────────────────────────

    def instrument_tool(self, tool_name: Optional[str] = None) -> Callable:
        """Decorator that wraps an async tool function with metrics recording.

        Usage::

            @metrics.instrument_tool("mitre_search")
            async def mitre_attack_search(query: str) -> list[dict]:
                ...

        If ``tool_name`` is omitted the wrapped function's ``__name__`` is used.
        """
        def decorator(func: Callable) -> Callable:
            name = tool_name or func.__name__

            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.monotonic()
                try:
                    result = await func(*args, **kwargs)
                    elapsed = time.monotonic() - start
                    self.tool_call(name, elapsed, status="success")
                    return result
                except Exception as exc:
                    elapsed = time.monotonic() - start
                    self.tool_call(name, elapsed, status="error")
                    raise

            return wrapper
        return decorator


# Global singleton — import and use anywhere in the service.
metrics = MetricsRegistry()
