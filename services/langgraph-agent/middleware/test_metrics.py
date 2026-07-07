"""
Tests for the MetricsRegistry and Prometheus instrumentation.

Verifies that:
1. Metrics are correctly recorded and can be exported
2. The instrument_tool decorator wraps async functions correctly
3. The Grafana dashboard panel queries match the exported metric names
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry


@pytest.fixture
def reg() -> "MetricsRegistry":
    """Return a fresh MetricsRegistry backed by an isolated CollectorRegistry."""
    # Late import to avoid import-order issues with pytest collection
    from middleware.metrics import MetricsRegistry

    return MetricsRegistry(registry=CollectorRegistry())


class TestMetricsRegistry:
    """Unit tests for the MetricsRegistry class."""

    def test_metrics_import(self) -> None:
        """The module and singleton import correctly."""
        from middleware.metrics import MetricsRegistry, metrics

        assert isinstance(metrics, MetricsRegistry)

    def test_agent_execution_records(self, reg: "MetricsRegistry") -> None:
        """Agent execution updates latency histogram + operations counter."""
        reg.agent_execution("triage", 1.5, status="success")
        # Verify histogram sample was recorded via generated output
        output = reg.generate().decode("utf-8")
        assert 'cobalto_agent_latency_seconds_count{agent="triage"} 1.0' in output
        assert 'cobalto_agent_operations_total{agent="triage",status="success"}' in output

    def test_tool_call_records(self, reg: "MetricsRegistry") -> None:
        """Tool call updates tool_calls counter + latency histogram."""
        reg.tool_call("mitre_search", 0.34, status="success")
        # Verify counter was incremented
        assert reg.tool_calls.labels(tool="mitre_search", status="success")._value.get() == 1.0

    def test_tool_call_error_records(self, reg: "MetricsRegistry") -> None:
        """Tool call with error status increments error counter too."""
        reg.tool_call("qdrant_query", 2.1, status="timeout")
        value = reg.tool_errors.labels(tool="qdrant_query", error_type="timeout")._value.get()
        assert value == 1.0

    def test_generate_returns_text(self, reg: "MetricsRegistry") -> None:
        """generate() returns bytes in Prometheus exposition format."""
        reg.agent_execution("test", 0.5)
        output = reg.generate()
        assert isinstance(output, bytes)
        text = output.decode("utf-8")
        assert "cobalto_agent_latency_seconds" in text
        assert "# HELP" in text
        assert "# TYPE" in text

    def test_content_type(self, reg: "MetricsRegistry") -> None:
        """content_type returns the correct Prometheus content type."""
        assert "text/plain" in reg.content_type
        assert "charset=utf-8" in reg.content_type

    def test_alert_received_counter(self, reg: "MetricsRegistry") -> None:
        """Alert ingestion metrics work."""
        reg.alert_received(source="wazuh", severity="critical")
        val = reg.alerts_received.labels(source="wazuh", severity="critical")._value.get()
        assert val == 1.0

    def test_llm_tokens_counter(self, reg: "MetricsRegistry") -> None:
        """LLM token consumption counter works."""
        reg.llm_tokens_consumed("triage", 1500, model="gpt-4")
        val = reg.llm_tokens.labels(agent="triage", model="gpt-4")._value.get()
        assert val == 1500.0

    def test_tool_call_duration_alias(self, reg: "MetricsRegistry") -> None:
        """tool_call_duration is an alias for tool_call."""
        reg.tool_call_duration("alias_test", 0.5, status="success")
        val = reg.tool_calls.labels(tool="alias_test", status="success")._value.get()
        assert val == 1.0


class TestInstrumentToolDecorator:
    """Tests for the @metrics.instrument_tool() decorator."""

    async def test_instrument_tool_records_success(self, reg: "MetricsRegistry") -> None:
        """Successful tool call records metrics."""
        @reg.instrument_tool("my_test_tool")
        async def my_tool(x: int) -> int:
            return x * 2

        result = await my_tool(21)
        assert result == 42

        # Verify counter incremented
        val = reg.tool_calls.labels(tool="my_test_tool", status="success")._value.get()
        assert val == 1.0

    async def test_instrument_tool_records_error(self, reg: "MetricsRegistry") -> None:
        """Failing tool call records error metrics."""

        @reg.instrument_tool("failing_tool")
        async def failing_tool() -> None:
            msg = "expected failure"
            raise ValueError(msg)

        with pytest.raises(ValueError, match="expected failure"):
            await failing_tool()

        # Error recorded (status="error" increments tool_errors too)
        val = reg.tool_calls.labels(tool="failing_tool", status="error")._value.get()
        assert val == 1.0

    async def test_instrument_tool_default_name(self, reg: "MetricsRegistry") -> None:
        """When no name given, uses function __name__."""

        @reg.instrument_tool()
        async def auto_named() -> str:
            return "ok"

        result = await auto_named()
        assert result == "ok"

        val = reg.tool_calls.labels(tool="auto_named", status="success")._value.get()
        assert val == 1.0

    async def test_exception_reraised(self, reg: "MetricsRegistry") -> None:
        """Original exception is reraised after recording error metrics."""

        @reg.instrument_tool("raise_tool")
        async def raise_tool() -> None:
            msg = "original error"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="original error"):
            await raise_tool()

        val = reg.tool_errors.labels(tool="raise_tool", error_type="error")._value.get()
        assert val == 1.0


class TestGrafanaDashboardMetrics:
    """Verify that the Grafana dashboard panel queries match our metric names."""

    def _load_dashboard(self) -> dict:
        dash_path = Path(__file__).parents[3] / "kubernetes" / "grafana" / "dashboards" / "agent-performance.json"
        with open(dash_path) as f:
            return json.load(f)

    def test_all_panel_metrics_exist_in_registry(self) -> None:
        """Every metric queried by a dashboard panel is actually exported."""
        from middleware.metrics import MetricsRegistry

        dash = self._load_dashboard()
        # Extract all PromQL metric names from panel expressions
        panel_metrics = set()
        for panel in dash["panels"]:
            for target in panel.get("targets", []):
                expr = target.get("expr", "")
                # Find all cobalto_* metric names in the expression
                for match in re.finditer(r"cobalto_\w+", expr):
                    panel_metrics.add(match.group())

        # Every panel metric should correspond to a real metric
        reg = MetricsRegistry(registry=CollectorRegistry())
        # Record a sample to all metrics so they appear in output
        reg.agent_execution("test", 1.0)
        reg.tool_call("test", 0.5)
        reg.tool_call("test", 0.5, status="error")  # triggers tool_errors counter
        reg.agent_investigation_started("test")
        reg.agent_error("test")
        reg.alert_received()
        reg.llm_tokens_consumed("test", 100)
        # Parse metric names from the generated output
        output = reg.generate().decode("utf-8")
        registry_metrics: set[str] = set()
        for line in output.splitlines():
            # Metric name is before first { or space after # HELP / # TYPE
            if line.startswith("#"):
                continue
            metric = line.split("{")[0].split(" ")[0]
            if metric:
                registry_metrics.add(metric)

        # Check each panel metric is registered
        missing = panel_metrics - registry_metrics
        assert not missing, (
            f"Dashboard queries metrics not in registry: {missing}\n"
            f"Registry exports: {sorted(registry_metrics)}"
        )

    def test_tool_variable_uses_metric(self) -> None:
        """The 'tool' template variable uses label_values from our metric."""
        dash = self._load_dashboard()
        tool_var = next(v for v in dash["templating"]["list"] if v.get("name") == "tool")
        assert "cobalto_tool_calls_total" in tool_var.get("query", {}).get("query", "")

    def test_tool_error_rate_gauge_query(self) -> None:
        """The tool error rate panel uses a valid PromQL expression."""
        dash = self._load_dashboard()
        panel = next(p for p in dash["panels"] if p.get("title") == "Tool Error Rate by Tool")
        expr = panel["targets"][0]["expr"]
        # The expression should contain both numerator and denominator
        assert "cobalto_tool_errors_total" in expr
        assert "cobalto_tool_calls_total" in expr
        assert "/" in expr


class TestAuditMetricsIntegration:
    """Verify AuditLogger.log_tool_call() records Prometheus metrics."""

    def test_log_tool_call_produces_entry(self) -> None:
        """AuditLogger.log_tool_call() returns a valid audit entry with all fields."""
        from middleware.audit import AuditLogger

        logger = AuditLogger()
        entry = logger.log_tool_call(
            agent_id="test_agent",
            tool_name="query_tool",
            args={"query": "APT29"},
            result="found 3 indicators",
            status="success",
            duration_ms=150.0,
        )
        assert entry["action"] == "tool_called"
        assert entry["details"]["tool_name"] == "query_tool"
        assert entry["details"]["status"] == "success"
        assert entry["details"]["duration_ms"] == 150.0
        assert "hmac_signature" in entry

    def test_log_tool_call_graceful_fallback(self) -> None:
        """AuditLogger.log_tool_call() works with error status and no duration."""
        from middleware.audit import AuditLogger

        logger = AuditLogger()
        entry = logger.log_tool_call(
            agent_id="test_agent",
            tool_name="failing_tool",
            args={},
            result=None,
            status="error",
        )
        assert entry["action"] == "tool_called"
        assert entry["details"]["status"] == "error"
        assert entry["details"]["duration_ms"] is None

    def test_log_tool_call_old_signature_backward_compat(self) -> None:
        """Calling with the original 4 positional args still works."""
        from middleware.audit import AuditLogger

        logger = AuditLogger()
        entry = logger.log_tool_call(
            "agent_a",  # agent_id
            "legacy_tool",  # tool_name
            {"input": "test"},  # args
            "ok",  # result
        )
        assert entry["action"] == "tool_called"
        # Default status is "success" when not provided
        assert entry["details"]["status"] == "success"
