"""
Integration tests for LangGraph Agent Service.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi.testclient import TestClient
from cobalto.testing.mock_services import MockWazuh, MockOpenCTI, MockTheHive, MockSlack, MockQdrant


@pytest.fixture
def mock_wazuh():
    """Create mock Wazuh instance."""
    wazuh = MockWazuh()
    wazuh.add_agent("agent-001", {"name": "webserver-01", "ip": "192.168.1.100"})
    return wazuh


@pytest.fixture
def mock_opencti():
    """Create mock OpenCTI instance."""
    opencti = MockOpenCTI()
    opencti.add_indicator("ind-001", {"name": "Malicious IP", "pattern": "[ipv4-addr:value = '203.0.113.45']"})
    return opencti


@pytest.fixture
def mock_thehive():
    """Create mock TheHive instance."""
    return MockTheHive()


@pytest.fixture
def mock_slack():
    """Create mock Slack instance."""
    return MockSlack()


@pytest.fixture
def mock_qdrant():
    """Create mock Qdrant instance."""
    return MockQdrant()


class TestMockServices:
    """Test mock services."""

    def test_mock_wazuh(self, mock_wazuh):
        """Test Wazuh mock."""
        agents = mock_wazuh.get_agents()
        assert len(agents) == 1
        assert agents[0]["name"] == "webserver-01"

    def test_mock_opencti(self, mock_opencti):
        """Test OpenCTI mock."""
        indicator = mock_opencti.get_indicator("ind-001")
        assert indicator is not None
        assert indicator["name"] == "Malicious IP"

    def test_mock_thehive(self, mock_thehive):
        """Test TheHive mock."""
        case = mock_thehive.create_case({"title": "Test Case"})
        assert case["title"] == "Test Case"
        assert case["status"] == "Open"

    def test_mock_slack(self, mock_slack):
        """Test Slack mock."""
        result = mock_slack.send_message("#test", "Hello")
        assert result["ok"] is True
        assert len(mock_slack.get_messages()) == 1

    def test_mock_qdrant(self, mock_qdrant):
        """Test Qdrant mock."""
        mock_qdrant.create_collection("test")
        mock_qdrant.insert_points("test", [{"id": "1", "vector": [0.1] * 1536}])
        results = mock_qdrant.search("test", [0.1] * 1536)
        assert len(results) > 0


class TestAgentWorkflow:
    """Test agent workflow integration."""

    @pytest.mark.asyncio
    async def test_triage_agent_workflow(self):
        """Test triage agent workflow."""
        from services.langgraph.agents.triage import TriageAgent

        agent = TriageAgent()
        result = await agent.run({
            "alert_id": "alert-001",
            "alert": {
                "source": "wazuh",
                "severity": "high",
                "source_ip": "203.0.113.45",
                "destination_ip": "192.168.1.100",
                "rule_id": "5712",
                "rule_description": "Brute force attack detected",
            },
        })

        assert result.status.value == "completed"
        assert "alert_id" in result.output
        assert "severity" in result.output

    @pytest.mark.asyncio
    async def test_analysis_agent_workflow(self):
        """Test analysis agent workflow."""
        from services.langgraph.agents.analysis import AnalysisAgent

        agent = AnalysisAgent()
        result = await agent.run({
            "alert_id": "alert-001",
            "alert": {
                "source": "wazuh",
                "severity": "high",
                "source_ip": "203.0.113.45",
                "destination_ip": "192.168.1.100",
                "rule_id": "5712",
                "rule_description": "Brute force attack detected",
            },
            "triage_result": {
                "alert_type": "brute-force",
                "indicators": [{"type": "ip", "value": "203.0.113.45"}],
            },
        })

        assert result.status.value == "completed"
        assert "attack_narrative" in result.output
        assert "mitre_mapping" in result.output

    @pytest.mark.asyncio
    async def test_threat_intel_agent_workflow(self):
        """Test threat intel agent workflow."""
        from services.langgraph.agents.threat_intel import ThreatIntelAgent

        agent = ThreatIntelAgent()
        result = await agent.run({
            "alert_id": "alert-001",
            "alert": {
                "source_ip": "203.0.113.45",
            },
            "indicators": [
                {"type": "ip", "value": "203.0.113.45"},
            ],
            "mitre_techniques": [
                {"id": "T1110", "name": "Brute Force"},
            ],
        })

        assert result.status.value == "completed"
        assert "threat_intel_results" in result.output

    @pytest.mark.asyncio
    async def test_response_agent_workflow(self):
        """Test response agent workflow."""
        from services.langgraph.agents.response import ResponseAgent

        agent = ResponseAgent()
        result = await agent.run({
            "alert_id": "alert-001",
            "alert": {
                "source_ip": "203.0.113.45",
                "host_name": "webserver-01",
                "user_name": "admin",
            },
            "analysis": {
                "alert_type": "brute-force",
                "risk_assessment": {"risk_score": 75},
            },
        })

        assert result.status.value == "completed"
        assert "containment_actions" in result.output
        assert "remediation_actions" in result.output


class TestWebhookIntegration:
    """Test webhook integration."""

    def test_webhook_handler_creation(self):
        """Test webhook handler creation."""
        from cobalto.soar.webhook_handler import WebhookHandler
        handler = WebhookHandler()
        assert handler.router is not None

    def test_wazuh_parser_integration(self):
        """Test Wazuh parser integration."""
        from cobalto.soar.webhook_handler import WebhookHandler, AlertSource
        handler = WebhookHandler()

        # Register parser
        parser = handler.create_wazuh_parser()
        handler.register_parser(AlertSource.WAZUH, parser)

        # Parse alert
        alert_data = {
            "data": {
                "id": 12345,
                "rule": {"id": 5712, "level": 8, "description": "Brute force"},
                "srcip": "203.0.113.45",
                "dstip": "192.168.1.100",
            }
        }

        result = parser(alert_data)
        assert result.source_ip == "203.0.113.45"
        assert result.severity == "high"


class TestMetricsIntegration:
    """Test metrics integration."""

    def test_http_metrics_recording(self):
        """Test HTTP metrics recording."""
        from cobalto.core.metrics import record_http_request
        # Should not raise
        record_http_request("test", "GET", "/test", 200, 0.5)

    def test_agent_metrics_recording(self):
        """Test agent metrics recording."""
        from cobalto.core.metrics import record_agent_execution
        record_agent_execution("test", "triage", "success", 2.5)

    def test_alert_metrics_recording(self):
        """Test alert metrics recording."""
        from cobalto.core.metrics import record_alert_processed
        record_alert_processed("test", "wazuh", "high", "received", 0.1)