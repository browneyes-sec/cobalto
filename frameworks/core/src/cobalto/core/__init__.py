"""
Cobalto Core Platform Framework
Shared utilities, configuration, logging, metrics, and tracing.
"""

from .config import Settings, get_settings
from .logging import setup_logging, get_logger
from .metrics import Metrics, get_metrics
from .tracing import setup_tracing, get_tracer
from .secrets import VaultClient, get_vault_client
from .health import HealthCheck, HealthStatus, ComponentHealth

__all__ = [
    "Settings",
    "get_settings",
    "setup_logging",
    "get_logger",
    "Metrics",
    "get_metrics",
    "setup_tracing",
    "get_tracer",
    "VaultClient",
    "get_vault_client",
    "HealthCheck",
    "HealthStatus",
    "ComponentHealth",
]