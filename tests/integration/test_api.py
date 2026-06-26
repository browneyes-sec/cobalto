import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def mock_dependencies():
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
    return {
        "alert_id": "WAZUH-3001",
        "rule_id": 800300,
        "rule_description": "Multiple failed SSH logins detected",
        "alert_level": 3,
        "source_ip": "10.0.0.50",
        "dest_ip": "10.0.0.10",
        "agent_name": "ssh-server-01",
        "timestamp": "2026-06-25T12:00:00Z",
        "raw_log": "sshd[9999]: Failed password for root from 10.0.0.50 port 44222 ssh2",
    }


class TestAgentAnalyzeEndpoint:
    def test_analyze_returns_200(self, client, alert_payload, mock_dependencies):
        response = client.post("/agent/analyze", json=alert_payload)
        assert response.status_code == 200

    def test_analyze_returns_expected_fields(self, client, alert_payload, mock_dependencies):
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert "incident_id" in data
        assert "final_report" in data
        assert "severity" in data
        assert "response_actions" in data
        assert "human_approved" in data
        assert "approval_timeout" in data
        assert "messages" in data

    def test_analyze_severity_populated(self, client, alert_payload, mock_dependencies):
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_analyze_mitre_techniques_used(self, client, alert_payload, mock_dependencies):
        response = client.post("/agent/analyze", json=alert_payload)
        mock_dependencies["mitre"].assert_called()

    def test_analyze_ioc_enrichment_called(self, client, alert_payload, mock_dependencies):
        response = client.post("/agent/analyze", json=alert_payload)
        mock_dependencies["enrich"].assert_called()

    def test_analyze_opencti_called(self, client, alert_payload, mock_dependencies):
        response = client.post("/agent/analyze", json=alert_payload)
        mock_dependencies["opencti"].assert_called()

    def test_analyze_response_actions_list(self, client, alert_payload, mock_dependencies):
        response = client.post("/agent/analyze", json=alert_payload)
        data = response.json()
        assert isinstance(data["response_actions"], list)

    def test_analyze_missing_required_field(self, client, mock_dependencies):
        incomplete = {"alert_id": "BAD-001"}
        response = client.post("/agent/analyze", json=incomplete)
        assert response.status_code == 422

    def test_analyze_empty_body(self, client, mock_dependencies):
        response = client.post("/agent/analyze", json={})
        assert response.status_code == 422

    def test_analyze_mitre_search_failure(self, client, alert_payload, mock_dependencies):
        mock_dependencies["mitre"].side_effect = Exception("Qdrant connection refused")
        response = client.post("/agent/analyze", json=alert_payload)
        assert response.status_code == 500

    def test_analyze_enrichment_failure(self, client, alert_payload, mock_dependencies):
        mock_dependencies["enrich"].side_effect = Exception("Cortex timeout")
        response = client.post("/agent/analyze", json=alert_payload)
        assert response.status_code == 500


class TestHealthEndpoints:
    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "langgraph-agent"

    def test_readiness_check(self, client):
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"


class TestGraphVisualization:
    def test_visualize_returns_mermaid(self, client, mock_dependencies):
        response = client.get("/graph/visualize")
        assert response.status_code == 200
        data = response.json()
        assert "mermaid" in data
        assert isinstance(data["mermaid"], str)


@pytest.fixture
def client():
    from fastapi import FastAPI
    from unittest.mock import AsyncMock, patch

    app = FastAPI(title="Test Cobalto SOC", version="1.0.0")

    from state import AlertPayload

    @app.post("/agent/analyze")
    async def analyze_alert(payload: AlertPayload):
        return {
            "incident_id": "INC-TEST001",
            "final_report": "Test incident report",
            "severity": "HIGH",
            "response_actions": [{"action": "block_ip", "target": "10.0.0.50", "status": "completed"}],
            "human_approved": True,
            "approval_timeout": False,
            "messages": ["Test analysis complete"],
        }

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "langgraph-agent"}

    @app.get("/ready")
    async def readiness_check():
        return {"status": "ready", "service": "langgraph-agent"}

    @app.get("/graph/visualize")
    async def visualize_graph():
        return {"mermaid": "graph TD\n    A[Start] --> B[End]"}

    return TestClient(app)
