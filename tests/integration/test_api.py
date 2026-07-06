"""
Integration tests for the LangGraph Agent API.

Tests the real FastAPI application end-to-end with mocked external
dependencies. Uses purpose-built test payloads that trigger deterministic
graph paths to avoid infinite loops (the human_approval_node loops back
to analysis for unapproved high-severity actions — only LOW severity
routes cleanly to documentation and END).

Tool-calling assertions are tested separately against threat_intel_agent
directly since the full graph integration path for HIGH severity enters
an infinite loop without an implemented approval_timeout mechanism.
"""

import os

# Set env vars BEFORE importing main — controls middleware at import time
os.environ.setdefault("COBALTO_DISABLE_AUTH", "true")
os.environ.setdefault("HMAC_SECRET", "integration-test-secret")
os.environ.setdefault("LOG_LEVEL", "WARNING")

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(autouse=True)
def _quiet_logs(monkeypatch):
    """Suppress logging during integration tests to reduce noise."""
    import logging
    logging.getLogger("cobalto.api").setLevel(logging.WARNING)
    logging.getLogger("cobalto.audit").setLevel(logging.WARNING)


@pytest.fixture
def mock_dependencies():
    """
    Patch external tool calls used by threat_intel_agent.

    These mocks MUST be applied before test requests so the deferred
    imports inside api.threat_intel_agent resolve to mocked versions.
    """
    with patch("tools.mitre_attack_search", new_callable=AsyncMock) as mock_mitre:
        with patch("tools.enrich_ioc", new_callable=AsyncMock) as mock_enrich:
            with patch("tools.opencti_query", new_callable=AsyncMock) as mock_opencti:
                mock_mitre.return_value = [
                    {
                        "technique_id": "TA0006",
                        "technique_name": "Credential Access",
                        "score": 0.85,
                        "description": "Adversaries may attempt to obtain credentials.",
                    }
                ]
                mock_enrich.return_value = {
                    "data": {"ip": "10.0.0.50", "positives": 5, "total": 70},
                }
                mock_opencti.return_value = {
                    "stixCoreObjects": {
                        "edges": [
                            {
                                "node": {
                                    "id": "threat-actor--1234",
                                    "standard_id": "threat-actor--1234",
                                    "name": "APT28",
                                    "description": "Russian state-sponsored group",
                                }
                            }
                        ]
                    }
                }
                yield {
                    "mitre": mock_mitre,
                    "enrich": mock_enrich,
                    "opencti": mock_opencti,
                }


@pytest.fixture
def alert_payload():
    """
    LOW-severity Wazuh-style alert.

    Uses alert_level=1 so triage routes to 'documentation' directly,
    which terminates cleanly (no human_approval_node loop).
    """
    return {
        "alert_id": "WAZUH-3001",
        "rule_id": 800300,
        "rule_description": "SSH login from unknown user",
        "alert_level": 1,
        "source_ip": "10.0.0.50",
        "dest_ip": "10.0.0.10",
        "agent_name": "ssh-server-01",
        "timestamp": "2026-06-25T12:00:00Z",
        "raw_log": "sshd[9999]: Failed password for root from 10.0.0.50 port 44222 ssh2",
    }


@pytest.fixture
def client():
    """Real FastAPI test client wired to the main application."""
    return TestClient(app)


class TestAgentAnalyzeEndpoint:
    """Tests for the POST /agent/analyze endpoint."""

    def test_analyze_returns_200(self, client, alert_payload, mock_dependencies):
        """A valid Wazuh-style payload should return 200 OK."""
        response = client.post("/agent/analyze", json=alert_payload)
        assert response.status_code == 200

    def test_analyze_returns_expected_fields(
        self, client, alert_payload, mock_dependencies
    ):
        """The response body should contain all AgentResult fields."""
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert "incident_id" in data
        assert "final_report" in data
        assert "severity" in data
        assert "response_actions" in data
        assert "human_approved" in data
        assert "approval_timeout" in data
        assert "messages" in data

    def test_analyze_severity_populated(
        self, client, alert_payload, mock_dependencies
    ):
        """The severity should be a valid SOC tier matching the payload."""
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        # alert_level=1 should produce LOW severity
        assert data["severity"] == "LOW"

    def test_analyze_response_actions_list(
        self, client, alert_payload, mock_dependencies
    ):
        """The response_actions field should be a list."""
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert isinstance(data["response_actions"], list)

    def test_analyze_incident_id_generated(
        self, client, alert_payload, mock_dependencies
    ):
        """An incident ID should be assigned by the documentation agent."""
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert data["incident_id"]
        assert data["incident_id"].startswith("INC-")

    def test_analyze_final_report_populated(
        self, client, alert_payload, mock_dependencies
    ):
        """The final_report should be a non-empty string."""
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert data["final_report"]
        assert "INCIDENT REPORT" in data["final_report"]

    def test_analyze_human_approved_for_low_path(
        self, client, alert_payload, mock_dependencies
    ):
        """
        LOW severity routes directly to documentation (bypasses
        human_approval_node), so human_approved stays at initial False.
        """
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        # The LOW path goes triage → documentation → END, never reaching
        # the human_approval_node, so human_approved remains False
        assert data["human_approved"] is False
        assert data["approval_timeout"] is False

    def test_analyze_missing_required_field(self, client, mock_dependencies):
        """Missing required fields should return 422."""
        incomplete = {"alert_id": "BAD-001"}
        response = client.post("/agent/analyze", json=incomplete)
        assert response.status_code == 422

    def test_analyze_empty_body(self, client, mock_dependencies):
        """An empty request body should return 422."""
        response = client.post("/agent/analyze", json={})
        assert response.status_code == 422

    def test_analyze_invalid_alert_level(
        self, client, mock_dependencies
    ):
        """An alert_level outside 1-4 should return 422."""
        payload = {
            "alert_id": "WAZUH-BAD",
            "rule_id": 800100,
            "rule_description": "Bad alert",
            "alert_level": 99,
            "source_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "agent_name": "test",
            "timestamp": "2026-06-25T12:00:00Z",
            "raw_log": "test alert",
        }
        response = client.post("/agent/analyze", json=payload)
        assert response.status_code == 422

    def test_analyze_additional_properties_rejected(
        self, client, mock_dependencies
    ):
        """Extra fields beyond the schema should be rejected."""
        payload = {
            "alert_id": "WAZUH-EXTRA",
            "rule_id": 800100,
            "rule_description": "Extra field test",
            "alert_level": 2,
            "source_ip": None,
            "dest_ip": None,
            "agent_name": "test",
            "timestamp": "2026-06-25T12:00:00Z",
            "raw_log": "test",
            "malicious_field": "injection",
        }
        response = client.post("/agent/analyze", json=payload)
        assert response.status_code == 422


class TestHealthEndpoints:
    """Tests for health and readiness probes."""

    def test_health_check(self, client):
        """The /health endpoint should return a healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "langgraph-agent"

    def test_readiness_check(self, client):
        """The /ready endpoint should return a ready status."""
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"


class TestGraphVisualization:
    """Tests for the graph visualization endpoint."""

    def test_visualize_returns_mermaid(self, client, mock_dependencies):
        """The /graph/visualize endpoint should return a Mermaid diagram."""
        response = client.get("/graph/visualize")
        assert response.status_code == 200
        data = response.json()
        assert "mermaid" in data
        assert isinstance(data["mermaid"], str)
        # Should reference graph nodes
        assert "triage" in data["mermaid"]


class TestThreatIntelAgentToolCalls:
    """
    Direct tests for threat_intel_agent tool call behavior.

    These tests exercise the async agent function directly with mocked
    tools to verify proper call counts, parameters, and error handling
    that the full graph path cannot test (due to the human_approval_node
    infinite loop for high-severity alerts).
    """

    @pytest.fixture
    def base_state(self, alert_payload):
        return {
            "alert": dict(alert_payload),
            "severity": "HIGH",
            "false_positive_probability": 0.05,
            "mitre_techniques": ["TA0006"],
            "attack_narrative": "",
            "affected_assets": ["10.0.0.10"],
            "threat_actor_matches": [],
            "ioc_enrichment": {},
            "response_actions": [],
            "human_approved": False,
            "approval_timeout": False,
            "incident_id": "",
            "final_report": "",
            "messages": [],
        }

    @pytest.mark.asyncio
    async def test_mitre_called_with_techniques(
        self, base_state, mock_dependencies
    ):
        """mitre_attack_search should be called for each MITRE technique."""
        from api import threat_intel_agent
        result = await threat_intel_agent(base_state)
        mock_dependencies["mitre"].assert_called()

    @pytest.mark.asyncio
    async def test_mitre_called_with_correct_query(
        self, base_state, mock_dependencies
    ):
        """The MITRE query should use the technique ID from triage."""
        from api import threat_intel_agent
        await threat_intel_agent(base_state)
        mock_dependencies["mitre"].assert_called_with("TA0006")

    @pytest.mark.asyncio
    async def test_enrich_called_with_source_ip(
        self, base_state, mock_dependencies
    ):
        """enrich_ioc should be called with the alert source IP."""
        from api import threat_intel_agent
        await threat_intel_agent(base_state)
        mock_dependencies["enrich"].assert_called()
        mock_dependencies["enrich"].assert_called_with("10.0.0.50")

    @pytest.mark.asyncio
    async def test_opencti_called_with_ip_pattern(
        self, base_state, mock_dependencies
    ):
        """opencti_query should be called with the source IP in STIX pattern."""
        from api import threat_intel_agent
        await threat_intel_agent(base_state)
        mock_dependencies["opencti"].assert_called()
        call_args = mock_dependencies["opencti"].call_args[0][0]
        assert "10.0.0.50" in call_args

    @pytest.mark.asyncio
    async def test_mitre_failure_does_not_crash(
        self, base_state, mock_dependencies
    ):
        """When mitre_attack_search fails, the agent should continue."""
        mock_dependencies["mitre"].side_effect = Exception("Qdrant down")
        from api import threat_intel_agent
        result = await threat_intel_agent(base_state)
        # Should have empty threat_actor_matches (not crash)
        assert result["threat_actor_matches"] == []

    @pytest.mark.asyncio
    async def test_enrich_failure_returns_fallback(
        self, base_state, mock_dependencies
    ):
        """
        When enrich_ioc fails, the agent should set enrichment_failed status.
        opencti_query still runs and may add additional enrichment data.
        """
        mock_dependencies["enrich"].side_effect = Exception("Cortex timeout")
        from api import threat_intel_agent
        result = await threat_intel_agent(base_state)
        # Fallback status should be present
        assert "status" in result["ioc_enrichment"]
        assert result["ioc_enrichment"]["status"] == "enrichment_failed"
        # opencti_query still runs and adds results
        assert "opencti" in result["ioc_enrichment"]

    @pytest.mark.asyncio
    async def test_multiple_mitre_techniques(
        self, base_state, mock_dependencies
    ):
        """Each MITRE technique should trigger an individual search."""
        state = dict(base_state)
        state["mitre_techniques"] = ["TA0006", "TA0008", "TA0010"]
        from api import threat_intel_agent
        await threat_intel_agent(state)
        assert mock_dependencies["mitre"].call_count == 3
