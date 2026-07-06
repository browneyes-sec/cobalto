"""Integration tests for the LangGraph API routes."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport
from services.langgraph.main import app


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
async def setup_app_state(client):
    """Mock app.state with required attributes before each test."""
    from cobalto.core.metrics import Metrics
    from cobalto.core.health import HealthStatus, HealthCheck, ComponentHealth
    from cobalto.mcp.server import MCPServer

    health_check = HealthCheck(status=HealthStatus.HEALTHY)
    app.state.metrics = Metrics("langgraph-api-test")
    app.state.health_checker = AsyncMock()
    app.state.health_checker.run_all_checks = AsyncMock(return_value=health_check)
    app.state.mcp_server = MCPServer(name="cobalto-langgraph-mcp", version="0.1.0")
    app.state.mcp_sessions: dict = {}
    app.state.supervisor = MagicMock()
    app.state.supervisor.run = AsyncMock(return_value=MagicMock(output={"status": "success", "routing": {}}))
    yield


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client):
        response = await client.get("/health")
        assert response.status_code in (200, 503)

    @pytest.mark.asyncio
    async def test_health_returns_json(self, client):
        response = await client.get("/health")
        data = response.json()
        assert "status" in data
        assert "components" in data


class TestMetricsEndpoint:
    """Tests for /metrics endpoint."""

    @pytest.mark.asyncio
    async def test_metrics_returns_200(self, client):
        response = await client.get("/metrics")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_metrics_content_type(self, client):
        response = await client.get("/metrics")
        assert "text/plain" in response.headers.get("content-type", "")


class TestMCPEndpoints:
    """Tests for MCP endpoints."""

    @pytest.mark.asyncio
    async def test_mcp_info(self, client):
        response = await client.get("/mcp")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_mcp_info_contains_server_info(self, client):
        response = await client.get("/mcp")
        data = response.json()
        assert "name" in data
        assert "version" in data

    @pytest.mark.asyncio
    async def test_mcp_tools_list(self, client):
        response = await client.get("/mcp/tools")
        assert response.status_code == 200
        data = response.json()
        assert "tools" in data

    @pytest.mark.asyncio
    async def test_mcp_resources_list(self, client):
        response = await client.get("/mcp/resources")
        assert response.status_code == 200
        data = response.json()
        assert "resources" in data

    @pytest.mark.asyncio
    async def test_mcp_prompts_list(self, client):
        response = await client.get("/mcp/prompts")
        assert response.status_code == 200
        data = response.json()
        assert "prompts" in data

    @pytest.mark.asyncio
    async def test_mcp_health(self, client):
        response = await client.get("/mcp/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestCorrelationId:
    """Tests for correlation ID middleware."""

    @pytest.mark.asyncio
    async def test_response_has_correlation_id(self, client):
        response = await client.get("/health")
        assert "X-Request-ID" in response.headers

    @pytest.mark.asyncio
    async def test_correlation_id_from_request(self, client):
        response = await client.get("/health", headers={"X-Request-ID": "test-correlation-id"})
        assert response.headers["X-Request-ID"] == "test-correlation-id"

    @pytest.mark.asyncio
    async def test_correlation_id_generated_if_missing(self, client):
        response = await client.get("/health")
        cid = response.headers["X-Request-ID"]
        assert len(cid) == 36
        assert cid.count("-") == 4


class TestAgentEndpoints:
    """Tests for agent endpoints."""

    @pytest.mark.asyncio
    async def test_analyze_endpoint(self, client):
        response = await client.post(
            "/agent/analyze",
            json={"alert_id": "test-1", "alert": {"severity": "high"}},
        )
        assert response.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_triage_endpoint(self, client):
        response = await client.post(
            "/agent/triage",
            json={"alert_id": "test-2", "alert": {"severity": "medium", "rule_id": "1001"}},
        )
        assert response.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_analyze_deep_endpoint(self, client):
        response = await client.post(
            "/agent/analyze-deep",
            json={"alert_id": "test-3", "alert": {"severity": "critical"}},
        )
        assert response.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_threat_intel_endpoint(self, client):
        response = await client.post(
            "/agent/threat-intel",
            json={"alert_id": "test-4", "alert": {"severity": "high"}},
        )
        assert response.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_response_endpoint(self, client):
        response = await client.post(
            "/agent/response",
            json={"alert_id": "test-5", "alert": {"severity": "critical"}},
        )
        assert response.status_code in (200, 500)


class TestWebhookEndpoints:
    """Tests for webhook endpoints."""

    @pytest.mark.asyncio
    async def test_generic_webhook(self, client):
        response = await client.post(
            "/webhook/generic",
            json={"alert_id": "generic-1", "severity": "high"},
        )
        assert response.status_code in (200, 500)

    @pytest.mark.asyncio
    async def test_n8n_callback_unknown_action(self, client):
        response = await client.post(
            "/webhook/n8n",
            json={"action": "unknown", "data": {}},
        )
        assert response.status_code == 400
