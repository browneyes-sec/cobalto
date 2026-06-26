import pytest
from unittest.mock import MagicMock, patch
import json


class MockAgent:
    def __init__(self, name: str, severity_map: dict | None = None):
        self.name = name
        self._severity_map = severity_map or {}

    def run(self, state: dict) -> dict:
        severity = state.get("alert", {}).get("severity", "low")
        if self.name == "triage":
            if severity in ("critical", "high"):
                state["triage_result"] = {
                    "severity_level": "HIGH",
                    "confidence": 0.95,
                    "false_positive_probability": 0.05,
                    "recommended_actions": ["isolate", "investigate"],
                    "category": "active_attack",
                }
            elif severity == "info":
                state["triage_result"] = {
                    "severity_level": "LOW",
                    "confidence": 0.9,
                    "false_positive_probability": 0.02,
                    "recommended_actions": ["log_only"],
                    "category": "informational",
                }
            else:
                state["triage_result"] = {
                    "severity_level": "MEDIUM",
                    "confidence": 0.7,
                    "false_positive_probability": 0.3,
                    "recommended_actions": ["investigate"],
                    "category": "suspicious",
                }
        elif self.name == "analysis":
            state["analysis_result"] = {
                "narrative": f"Analysis of {state.get('alert', {}).get('title', 'unknown alert')}: "
                "Detected brute force pattern with high confidence. "
                "Attack originated from external IP targeting critical infrastructure.",
                "affected_assets": state.get("alert", {}).get("affected_assets", []),
                "attack_path": ["initial_access", "credential_access", "lateral_movement"],
                "risk_score": 8.5,
            }
        elif self.name == "threat_intel":
            state["threat_intel_result"] = {
                "enrichment": {
                    "ip_reputation": "malicious",
                    "known_campaigns": ["OperationBruteForce2026"],
                    "attribution": "unknown",
                    "related_iocs": ["203.0.113.42", "203.0.113.43"],
                },
                "mitre_mappings": [
                    {"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.95},
                    {"technique_id": "T1078", "technique_name": "Valid Accounts", "confidence": 0.80},
                ],
            }
        elif self.name == "response":
            triage = state.get("triage_result", {})
            if triage.get("severity_level") == "HIGH":
                state["response_result"] = {
                    "actions": [
                        {"type": "isolate_host", "target": "WS-PROD-17", "status": "pending_approval"},
                        {"type": "block_ip", "target": "203.0.113.42", "status": "pending_approval"},
                        {"type": "reset_password", "target": "admin", "status": "pending_approval"},
                    ],
                    "containment_level": "aggressive",
                }
            else:
                state["response_result"] = {
                    "actions": [
                        {"type": "create_ticket", "target": "SOC-TICKET-001", "status": "created"},
                    ],
                    "containment_level": "passive",
                }
        elif self.name == "documentation":
            state["documentation_result"] = {
                "report_title": f"Incident Report - {state.get('alert', {}).get('title', 'Unknown')}",
                "executive_summary": "Security incident requiring immediate attention.",
                "technical_details": {
                    "triage": state.get("triage_result"),
                    "analysis": state.get("analysis_result"),
                    "threat_intel": state.get("threat_intel_result"),
                    "response": state.get("response_result"),
                },
                "recommendations": ["Implement MFA", "Review access controls"],
                "status": "complete",
            }
        elif self.name == "escalate":
            state["escalation_result"] = {
                "escalation_level": "L2_SOC",
                "reason": "High severity alert requiring senior analyst review",
                "assigned_team": "SOC-L2-IncidentResponse",
                "sla_deadline": "4_hours",
                "escalation_ticket": "ESC-2026-001",
            }
        return state


@pytest.fixture
def triage_agent():
    return MockAgent("triage")


@pytest.fixture
def analysis_agent():
    return MockAgent("analysis")


@pytest.fixture
def threat_intel_agent():
    return MockAgent("threat_intel")


@pytest.fixture
def response_agent():
    return MockAgent("response")


@pytest.fixture
def documentation_agent():
    return MockAgent("documentation")


@pytest.fixture
def escalate_agent():
    return MockAgent("escalate")


class TestTriageAgent:
    def test_triage_agent_high_severity(self, triage_agent, sample_alert_payload):
        state = {"alert": sample_alert_payload}
        result = triage_agent.run(state)
        assert result["triage_result"]["severity_level"] == "HIGH"
        assert result["triage_result"]["confidence"] > 0.9
        assert result["triage_result"]["false_positive_probability"] < 0.1
        assert "isolate" in result["triage_result"]["recommended_actions"]

    def test_triage_agent_low_severity(self, triage_agent, sample_alert_payload_low):
        state = {"alert": sample_alert_payload_low}
        result = triage_agent.run(state)
        assert result["triage_result"]["severity_level"] == "LOW"
        assert result["triage_result"]["category"] == "informational"
        assert "log_only" in result["triage_result"]["recommended_actions"]

    def test_triage_agent_false_positive(self, triage_agent, sample_false_positive_alert):
        state = {"alert": sample_false_positive_alert}
        result = triage_agent.run(state)
        assert result["triage_result"]["false_positive_probability"] > 0.25
        assert result["triage_result"]["severity_level"] == "MEDIUM"


class TestAnalysisAgent:
    def test_analysis_agent(self, analysis_agent, sample_alert_payload):
        state = {"alert": sample_alert_payload}
        result = analysis_agent.run(state)
        assert "narrative" in result["analysis_result"]
        assert len(result["analysis_result"]["narrative"]) > 0
        assert "affected_assets" in result["analysis_result"]
        assert len(result["analysis_result"]["affected_assets"]) > 0
        assert result["analysis_result"]["risk_score"] > 0


class TestThreatIntelAgent:
    def test_threat_intel_agent(self, threat_intel_agent, sample_alert_payload):
        state = {"alert": sample_alert_payload}
        result = threat_intel_agent.run(state)
        assert "enrichment" in result["threat_intel_result"]
        assert result["threat_intel_result"]["enrichment"]["ip_reputation"] == "malicious"
        assert "mitre_mappings" in result["threat_intel_result"]
        assert len(result["threat_intel_result"]["mitre_mappings"]) > 0


class TestResponseAgent:
    def test_response_agent_high_severity(self, response_agent):
        state = {
            "alert": {"severity": "high"},
            "triage_result": {"severity_level": "HIGH"},
        }
        result = response_agent.run(state)
        assert len(result["response_result"]["actions"]) >= 2
        assert result["response_result"]["containment_level"] == "aggressive"
        action_types = [a["type"] for a in result["response_result"]["actions"]]
        assert "isolate_host" in action_types
        assert "block_ip" in action_types

    def test_response_agent_low_severity(self, response_agent):
        state = {
            "alert": {"severity": "low"},
            "triage_result": {"severity_level": "LOW"},
        }
        result = response_agent.run(state)
        assert result["response_result"]["containment_level"] == "passive"
        assert len(result["response_result"]["actions"]) == 1
        assert result["response_result"]["actions"][0]["type"] == "create_ticket"


class TestHumanApprovalNode:
    def test_human_approval_node_high_impact(self):
        def human_approval(state):
            response = state.get("response_result", {})
            actions = response.get("actions", [])
            high_impact_actions = [
                a for a in actions if a.get("type") in ("isolate_host", "block_ip")
            ]
            if high_impact_actions:
                state["approval_required"] = True
                state["approval_status"] = "pending"
            else:
                state["approval_required"] = False
                state["approval_status"] = "auto_approved"
            return state

        state = {
            "response_result": {
                "actions": [
                    {"type": "isolate_host", "target": "WS-PROD-17"},
                    {"type": "block_ip", "target": "203.0.113.42"},
                ]
            }
        }
        result = human_approval(state)
        assert result["approval_required"] is True
        assert result["approval_status"] == "pending"

    def test_human_approval_node_low_impact(self):
        def human_approval(state):
            response = state.get("response_result", {})
            actions = response.get("actions", [])
            high_impact_actions = [
                a for a in actions if a.get("type") in ("isolate_host", "block_ip")
            ]
            if high_impact_actions:
                state["approval_required"] = True
                state["approval_status"] = "pending"
            else:
                state["approval_required"] = False
                state["approval_status"] = "auto_approved"
            return state

        state = {
            "response_result": {
                "actions": [
                    {"type": "create_ticket", "target": "SOC-TICKET-001"},
                ]
            }
        }
        result = human_approval(state)
        assert result["approval_required"] is False
        assert result["approval_status"] == "auto_approved"


class TestDocumentationAgent:
    def test_documentation_agent(self, documentation_agent, sample_alert_payload):
        state = {
            "alert": sample_alert_payload,
            "triage_result": {"severity_level": "HIGH", "confidence": 0.95},
            "analysis_result": {"narrative": "Test narrative", "affected_assets": ["WS-PROD-17"]},
            "threat_intel_result": {"enrichment": {"ip_reputation": "malicious"}},
            "response_result": {"actions": [{"type": "isolate_host"}]},
        }
        result = documentation_agent.run(state)
        assert "report_title" in result["documentation_result"]
        assert "executive_summary" in result["documentation_result"]
        assert "technical_details" in result["documentation_result"]
        assert result["documentation_result"]["status"] == "complete"
        assert "recommendations" in result["documentation_result"]


class TestEscalateAgent:
    def test_escalate_agent(self, escalate_agent):
        state = {
            "triage_result": {"severity_level": "HIGH"},
            "alert": {"title": "Critical Incident"},
        }
        result = escalate_agent.run(state)
        assert "escalation_level" in result["escalation_result"]
        assert "reason" in result["escalation_result"]
        assert "assigned_team" in result["escalation_result"]
        assert "sla_deadline" in result["escalation_result"]
        assert result["escalation_result"]["escalation_level"] == "L2_SOC"
