import pytest
from unittest.mock import MagicMock, patch, AsyncMock


class MockWorkflow:
    def __init__(self):
        self._nodes = {}
        self._state = {}

    def add_node(self, name: str, func):
        self._nodes[name] = func

    def run(self, initial_state: dict) -> dict:
        state = dict(initial_state)
        execution_order = []
        current = "triage"
        visited = set()

        while current and current not in visited:
            visited.add(current)
            execution_order.append(current)
            if current in self._nodes:
                state = self._nodes[current](state)

            triage = state.get("triage_result", {})
            severity = triage.get("severity_level", "")
            fp_prob = triage.get("false_positive_probability", 0)

            if current == "triage":
                if fp_prob > 0.5:
                    current = "documentation"
                elif severity in ("HIGH", "CRITICAL"):
                    current = "analysis"
                else:
                    current = "documentation"
            elif current == "analysis":
                current = "threat_intel"
            elif current == "threat_intel":
                current = "response"
            elif current == "response":
                actions = state.get("response_result", {}).get("actions", [])
                high_impact = [a for a in actions if a["type"] in ("isolate_host", "block_ip")]
                if high_impact:
                    state["approval_required"] = True
                    state["approval_status"] = "approved"
                else:
                    state["approval_required"] = False
                    state["approval_status"] = "auto_approved"
                current = "documentation"
            elif current == "documentation":
                current = None

        state["execution_order"] = execution_order
        return state


def make_triage(state):
    severity = state.get("alert", {}).get("severity", "low")
    title = state.get("alert", {}).get("title", "")
    is_test = "test" in title.lower() or "scheduled" in title.lower()

    if is_test:
        fp_prob = 0.8
        sev_level = "LOW"
    elif severity in ("critical", "high"):
        fp_prob = 0.05
        sev_level = "HIGH"
    elif severity == "info":
        fp_prob = 0.02
        sev_level = "LOW"
    else:
        fp_prob = 0.3
        sev_level = "MEDIUM"

    state["triage_result"] = {
        "severity_level": sev_level,
        "confidence": 0.95 if sev_level == "HIGH" else 0.7,
        "false_positive_probability": fp_prob,
        "recommended_actions": ["isolate"] if sev_level == "HIGH" else ["log_only"],
        "category": "active_attack" if sev_level == "HIGH" else "informational",
    }
    return state


def make_analysis(state):
    alert = state.get("alert", {})
    state["analysis_result"] = {
        "narrative": f"Analysis of {alert.get('title', 'unknown')}: "
        "Detected attack pattern with high confidence.",
        "affected_assets": alert.get("affected_assets", []),
        "attack_path": ["initial_access", "credential_access"],
        "risk_score": 8.5,
    }
    return state


def make_threat_intel(state):
    state["threat_intel_result"] = {
        "enrichment": {
            "ip_reputation": "malicious",
            "known_campaigns": ["OperationBruteForce2026"],
        },
        "mitre_mappings": [
            {"technique_id": "T1110", "technique_name": "Brute Force", "confidence": 0.95},
        ],
    }
    return state


def make_response(state):
    triage = state.get("triage_result", {})
    if triage.get("severity_level") == "HIGH":
        state["response_result"] = {
            "actions": [
                {"type": "isolate_host", "target": "WS-PROD-17", "status": "pending"},
                {"type": "block_ip", "target": "203.0.113.42", "status": "pending"},
            ],
            "containment_level": "aggressive",
        }
    else:
        state["response_result"] = {
            "actions": [
                {"type": "create_ticket", "target": "SOC-001", "status": "created"},
            ],
            "containment_level": "passive",
        }
    return state


def make_documentation(state):
    state["documentation_result"] = {
        "report_title": f"Incident Report - {state.get('alert', {}).get('title', 'Unknown')}",
        "executive_summary": "Security incident report.",
        "technical_details": {
            "triage": state.get("triage_result"),
            "analysis": state.get("analysis_result"),
            "threat_intel": state.get("threat_intel_result"),
            "response": state.get("response_result"),
        },
        "recommendations": ["Implement MFA", "Review access controls"],
        "status": "complete",
    }
    return state


@pytest.fixture
def workflow():
    wf = MockWorkflow()
    wf.add_node("triage", make_triage)
    wf.add_node("analysis", make_analysis)
    wf.add_node("threat_intel", make_threat_intel)
    wf.add_node("response", make_response)
    wf.add_node("documentation", make_documentation)
    return wf


@pytest.fixture
def high_severity_alert():
    return {
        "alert_id": "ALT-INT-001",
        "title": "Brute Force Attack Detected",
        "severity": "high",
        "source": "EDR-SentinelOne",
        "timestamp": "2026-06-25T10:30:00Z",
        "description": "500+ failed login attempts from external IP",
        "affected_assets": ["WS-PROD-17", "DC-PRIMARY"],
        "indicators": [{"type": "ip", "value": "203.0.113.42"}],
    }


@pytest.fixture
def low_severity_alert():
    return {
        "alert_id": "ALT-INT-002",
        "title": "DNS Query Logged",
        "severity": "info",
        "source": "SIEM-Splunk",
        "timestamp": "2026-06-25T11:00:00Z",
        "description": "Routine DNS query logged from internal host",
        "affected_assets": ["APP-SRV-03"],
        "indicators": [{"type": "hostname", "value": "APP-SRV-03"}],
    }


@pytest.fixture
def false_positive_alert():
    return {
        "alert_id": "ALT-INT-003",
        "title": "Port Scan Detected - Test Alert",
        "severity": "medium",
        "source": "IDS-Snort",
        "timestamp": "2026-06-25T12:00:00Z",
        "description": "Scheduled vulnerability scan from security team",
        "affected_assets": ["SCAN-SERVER-01"],
        "indicators": [{"type": "ip", "value": "10.0.1.50"}],
    }


class TestFullWorkflowTriageToDocumentation:
    def test_full_workflow_triage_to_documentation(self, workflow, high_severity_alert):
        initial_state = {"alert": high_severity_alert}
        result = workflow.run(initial_state)
        assert "triage_result" in result
        assert "analysis_result" in result
        assert "threat_intel_result" in result
        assert "response_result" in result
        assert "documentation_result" in result
        assert result["documentation_result"]["status"] == "complete"
        assert "triage" in result["execution_order"]
        assert "analysis" in result["execution_order"]
        assert "documentation" in result["execution_order"]


class TestWorkflowHighSeverityPath:
    def test_workflow_high_severity_path(self, workflow, high_severity_alert):
        initial_state = {"alert": high_severity_alert}
        result = workflow.run(initial_state)
        assert result["triage_result"]["severity_level"] == "HIGH"
        assert result["analysis_result"]["risk_score"] > 0
        assert result["threat_intel_result"]["enrichment"]["ip_reputation"] == "malicious"
        assert result["response_result"]["containment_level"] == "aggressive"
        action_types = [a["type"] for a in result["response_result"]["actions"]]
        assert "isolate_host" in action_types
        assert "block_ip" in action_types
        assert result["approval_required"] is True
        assert result["documentation_result"]["status"] == "complete"


class TestWorkflowLowSeverityPath:
    def test_workflow_low_severity_path(self, workflow, low_severity_alert):
        initial_state = {"alert": low_severity_alert}
        result = workflow.run(initial_state)
        assert result["triage_result"]["severity_level"] == "LOW"
        assert result["triage_result"]["false_positive_probability"] < 0.1
        assert "analysis" not in result["execution_order"]
        assert "threat_intel" not in result["execution_order"]
        assert "response" not in result["execution_order"]
        assert result["documentation_result"]["status"] == "complete"


class TestWorkflowFalsePositivePath:
    def test_workflow_false_positive_path(self, workflow, false_positive_alert):
        initial_state = {"alert": false_positive_alert}
        result = workflow.run(initial_state)
        assert result["triage_result"]["false_positive_probability"] > 0.5
        assert "analysis" not in result["execution_order"]
        assert "threat_intel" not in result["execution_order"]
        assert "response" not in result["execution_order"]
        assert result["documentation_result"]["status"] == "complete"

    def test_workflow_auto_closes_on_high_fp(self, workflow):
        alert = {
            "alert_id": "ALT-FP-001",
            "title": "Test Alert - Scheduled Scan",
            "severity": "medium",
            "source": "test",
            "timestamp": "2026-06-25T12:00:00Z",
            "affected_assets": [],
        }
        result = workflow.run({"alert": alert})
        assert result["triage_result"]["false_positive_probability"] > 0.5
        assert result["documentation_result"]["status"] == "complete"
        assert result["execution_order"] == ["triage", "documentation"]
