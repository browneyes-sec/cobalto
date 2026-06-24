"""
Prometheus metrics collection and exposition.
Provides standardized metrics for all Cobalto services.
"""

from functools import lru_cache
from typing import Optional, Dict, Any
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST


class Metrics:
    """Centralized metrics registry and collectors."""

    def __init__(self, service_name: str, registry: Optional[CollectorRegistry] = None):
        self.service_name = service_name
        self.registry = registry or CollectorRegistry()
        self._counters: Dict[str, Counter] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._setup_default_metrics()

    def _setup_default_metrics(self) -> None:
        """Initialize default metrics for all services."""
        self._counters["http_requests_total"] = Counter(
            "http_requests_total",
            "Total HTTP requests",
            ["method", "endpoint", "status"],
            registry=self.registry,
        )
        self._histograms["http_request_duration_seconds"] = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency in seconds",
            ["method", "endpoint"],
            buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=self.registry,
        )
        self._counters["agent_executions_total"] = Counter(
            "agent_executions_total",
            "Total agent executions",
            ["agent_type", "status"],
            registry=self.registry,
        )
        self._histograms["agent_execution_duration_seconds"] = Histogram(
            "agent_execution_duration_seconds",
            "Agent execution latency in seconds",
            ["agent_type"],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
            registry=self.registry,
        )
        self._counters["alerts_processed_total"] = Counter(
            "alerts_processed_total",
            "Total alerts processed",
            ["source", "severity", "disposition"],
            registry=self.registry,
        )
        self._histograms["alert_processing_duration_seconds"] = Histogram(
            "alert_processing_duration_seconds",
            "Alert processing latency in seconds",
            ["source"],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
            registry=self.registry,
        )
        self._counters["mitre_queries_total"] = Counter(
            "mitre_queries_total",
            "Total MITRE ATT&CK queries",
            ["query_type", "result"],
            registry=self.registry,
        )
        self._counters["enrichment_requests_total"] = Counter(
            "enrichment_requests_total",
            "Total enrichment requests",
            ["enricher", "observable_type", "status"],
            registry=self.registry,
        )
        self._histograms["enrichment_duration_seconds"] = Histogram(
            "enrichment_duration_seconds",
            "Enrichment latency in seconds",
            ["enricher"],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
            registry=self.registry,
        )
        self._counters["response_actions_total"] = Counter(
            "response_actions_total",
            "Total response actions executed",
            ["action_type", "target_type", "status"],
            registry=self.registry,
        )
        self._histograms["response_action_duration_seconds"] = Histogram(
            "response_action_duration_seconds",
            "Response action execution latency",
            ["action_type"],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
            registry=self.registry,
        )
        self._counters["cases_total"] = Counter(
            "cases_total",
            "Total cases",
            ["status", "severity"],
            registry=self.registry,
        )
        self._gauges["active_cases"] = Gauge(
            "active_cases",
            "Currently active cases",
            ["severity"],
            registry=self.registry,
        )
        self._counters["external_api_requests_total"] = Counter(
            "external_api_requests_total",
            "Total external API requests",
            ["api", "endpoint", "status"],
            registry=self.registry,
        )
        self._histograms["external_api_duration_seconds"] = Histogram(
            "external_api_duration_seconds",
            "External API latency in seconds",
            ["api", "endpoint"],
            buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
            registry=self.registry,
        )

    def counter(self, name: str, labels: Optional[Dict[str, str]] = None) -> Counter:
        if name not in self._counters:
            raise KeyError(f"Counter '{name}' not found")
        return self._counters[name].labels(**(labels or {}))

    def histogram(self, name: str, labels: Optional[Dict[str, str]] = None) -> Histogram:
        if name not in self._histograms:
            raise KeyError(f"Histogram '{name}' not found")
        return self._histograms[name].labels(**(labels or {}))

    def gauge(self, name: str, labels: Optional[Dict[str, str]] = None) -> Gauge:
        if name not in self._gauges:
            raise KeyError(f"Gauge '{name}' not found")
        return self._gauges[name].labels(**(labels or {}))

    def increment_counter(self, name: str, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        self.counter(name, labels).inc(value)

    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        self.histogram(name, labels).observe(value)

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        self.gauge(name, labels).set(value)

    def get_metrics(self) -> bytes:
        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        return CONTENT_TYPE_LATEST


def record_http_request(service_name: str, method: str, endpoint: str, status: int, duration: float) -> None:
    metrics = get_metrics(service_name)
    metrics.increment_counter("http_requests_total", {"method": method, "endpoint": endpoint, "status": str(status)})
    metrics.observe_histogram("http_request_duration_seconds", duration, {"method": method, "endpoint": endpoint})


def record_agent_execution(service_name: str, agent_type: str, status: str, duration: float) -> None:
    metrics = get_metrics(service_name)
    metrics.increment_counter("agent_executions_total", {"agent_type": agent_type, "status": status})
    metrics.observe_histogram("agent_execution_duration_seconds", duration, {"agent_type": agent_type})


def record_alert_processed(service_name: str, source: str, severity: str, disposition: str, duration: float) -> None:
    metrics = get_metrics(service_name)
    metrics.increment_counter("alerts_processed_total", {"source": source, "severity": severity, "disposition": disposition})
    metrics.observe_histogram("alert_processing_duration_seconds", duration, {"source": source})


def record_mitre_query(service_name: str, query_type: str, result: str, duration: float) -> None:
    metrics = get_metrics(service_name)
    metrics.increment_counter("mitre_queries_total", {"query_type": query_type, "result": result})


def record_enrichment(service_name: str, enricher: str, observable_type: str, status: str, duration: float) -> None:
    metrics = get_metrics(service_name)
    metrics.increment_counter("enrichment_requests_total", {"enricher": enricher, "observable_type": observable_type, "status": status})
    metrics.observe_histogram("enrichment_duration_seconds", duration, {"enricher": enricher})


def record_response_action(service_name: str, action_type: str, target_type: str, status: str, duration: float) -> None:
    metrics = get_metrics(service_name)
    metrics.increment_counter("response_actions_total", {"action_type": action_type, "target_type": target_type, "status": status})
    metrics.observe_histogram("response_action_duration_seconds", duration, {"action_type": action_type})


def record_external_request(service_name: str, api: str, endpoint: str, status: str, duration: float) -> None:
    metrics = get_metrics(service_name)
    metrics.increment_counter("external_api_requests_total", {"api": api, "endpoint": endpoint, "status": status})
    metrics.observe_histogram("external_api_duration_seconds", duration, {"api": api, "endpoint": endpoint})


@lru_cache
def get_metrics(service_name: str) -> Metrics:
    return Metrics(service_name)