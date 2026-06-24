"""
Unit tests for core framework.
"""

import pytest
import os
from unittest.mock import patch, MagicMock


class TestConfig:
    """Test configuration management."""

    def test_settings_defaults(self):
        """Test default settings values."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "WAZUH_PASSWORD": "test_password",
            "OPENCTI_TOKEN": "test_token",
            "THEHIVE_TOKEN": "test_token",
            "CORTEX_TOKEN": "test_token",
            "N8N_API_KEY": "test_key",
            "N8N_WEBHOOK_SECRET": "test_secret",
            "LANGGRAPH_API_KEY": "test_key",
            "JWT_SECRET_KEY": "test_jwt_secret",
        }):
            from cobalto.core.config import Settings
            settings = Settings()
            assert settings.app_name == "cobalto"
            assert settings.api_port == 8000
            assert settings.log_level == "INFO"

    def test_settings_validation(self):
        """Test settings validation."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "WAZUH_PASSWORD": "test_password",
            "OPENCTI_TOKEN": "test_token",
            "THEHIVE_TOKEN": "test_token",
            "CORTEX_TOKEN": "test_token",
            "N8N_API_KEY": "test_key",
            "N8N_WEBHOOK_SECRET": "test_secret",
            "LANGGRAPH_API_KEY": "test_key",
            "JWT_SECRET_KEY": "test_jwt_secret",
            "LOG_LEVEL": "INVALID",
        }):
            from cobalto.core.config import Settings
            with pytest.raises(Exception):
                Settings()

    def test_environment_properties(self):
        """Test environment property helpers."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "WAZUH_PASSWORD": "test_password",
            "OPENCTI_TOKEN": "test_token",
            "THEHIVE_TOKEN": "test_token",
            "CORTEX_TOKEN": "test_token",
            "N8N_API_KEY": "test_key",
            "N8N_WEBHOOK_SECRET": "test_secret",
            "LANGGRAPH_API_KEY": "test_key",
            "JWT_SECRET_KEY": "test_jwt_secret",
            "APP_ENV": "production",
        }):
            from cobalto.core.config import Settings
            settings = Settings()
            assert settings.is_production is True
            assert settings.is_development is False


class TestLogging:
    """Test logging utilities."""

    def test_setup_logging(self):
        """Test logging setup."""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "REDIS_URL": "redis://localhost:6379/0",
            "WAZUH_PASSWORD": "test_password",
            "OPENCTI_TOKEN": "test_token",
            "THEHIVE_TOKEN": "test_token",
            "CORTEX_TOKEN": "test_token",
            "N8N_API_KEY": "test_key",
            "N8N_WEBHOOK_SECRET": "test_secret",
            "LANGGRAPH_API_KEY": "test_key",
            "JWT_SECRET_KEY": "test_jwt_secret",
        }):
            from cobalto.core.logging import setup_logging
            setup_logging(log_level="DEBUG", log_format="json")

    def test_get_logger(self):
        """Test logger creation."""
        from cobalto.core.logging import get_logger
        logger = get_logger("test")
        assert logger is not None

    def test_log_context(self):
        """Test log context manager."""
        from cobalto.core.logging import LogContext
        with LogContext(request_id="123", user_id="test"):
            # Context should be active here
            pass
        # Context should be cleaned up


class TestMetrics:
    """Test metrics collection."""

    def test_metrics_creation(self):
        """Test metrics instance creation."""
        from cobalto.core.metrics import Metrics
        metrics = Metrics("test-service")
        assert metrics.service_name == "test-service"

    def test_counter_increment(self):
        """Test counter increment."""
        from cobalto.core.metrics import Metrics
        metrics = Metrics("test-service")
        metrics.increment_counter("http_requests_total", {"method": "GET", "endpoint": "/test", "status": "200"})
        # No assertion needed, just ensure it doesn't raise

    def test_histogram_observe(self):
        """Test histogram observation."""
        from cobalto.core.metrics import Metrics
        metrics = Metrics("test-service")
        metrics.observe_histogram("http_request_duration_seconds", 0.5, {"method": "GET", "endpoint": "/test"})

    def test_gauge_set(self):
        """Test gauge set."""
        from cobalto.core.metrics import Metrics
        metrics = Metrics("test-service")
        metrics.set_gauge("active_cases", 5.0, {"severity": "high"})

    def test_get_metrics(self):
        """Test metrics output generation."""
        from cobalto.core.metrics import Metrics
        metrics = Metrics("test-service")
        output = metrics.get_metrics()
        assert isinstance(output, bytes)


class TestHealth:
    """Test health check utilities."""

    @pytest.mark.asyncio
    async def test_health_checker_creation(self):
        """Test health checker creation."""
        from cobalto.core.health import HealthChecker
        checker = HealthChecker("test-service")
        assert checker.service_name == "test-service"

    def test_health_status(self):
        """Test health status enum."""
        from cobalto.core.health import HealthStatus
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"

    def test_component_health(self):
        """Test component health dataclass."""
        from cobalto.core.health import ComponentHealth, HealthStatus
        health = ComponentHealth(
            name="test",
            status=HealthStatus.HEALTHY,
            message="All good",
        )
        assert health.name == "test"
        assert health.status == HealthStatus.HEALTHY

    def test_health_check_to_dict(self):
        """Test health check serialization."""
        from cobalto.core.health import HealthCheck, HealthStatus
        check = HealthCheck(status=HealthStatus.HEALTHY)
        result = check.to_dict()
        assert result["status"] == "healthy"
        assert "components" in result


class TestSecrets:
    """Test secrets management."""

    def test_vault_client_creation(self):
        """Test Vault client creation."""
        from cobalto.core.secrets import VaultClient
        client = VaultClient(url="http://localhost:8200")
        assert client.url == "http://localhost:8200"

    def test_vault_client_write_read(self):
        """Test Vault write and read."""
        from cobalto.core.secrets import VaultClient
        client = VaultClient(url="http://localhost:8200")
        # Mock the client
        client._client = MagicMock()
        client._client.secrets.kv.v2.create_or_update_secret.return_value = None
        client._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"key": "value"}}
        }
        # Test write
        result = client.write_secret("test/path", {"key": "value"})
        assert result is True
        # Test read
        data = client.read_secret("test/path")
        assert data == {"key": "value"}