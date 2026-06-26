import pytest
from typing import Optional
from state import SOCAgentState, AlertPayload


class TestAlertPayload:
    def test_valid_alert_payload(self):
        alert = AlertPayload(
            alert_id="WAZUH-1001",
            rule_id=800100,
            rule_description="SSH brute force attempt",
            alert_level=3,
            source_ip="10.0.0.50",
            dest_ip="10.0.0.10",
            agent_name="web-server-01",
            timestamp="2026-06-25T10:30:00Z",
            raw_log="sshd[12345]: Failed password for root from 10.0.0.50 port 22 ssh2",
        )
        assert alert.alert_id == "WAZUH-1001"
        assert alert.alert_level == 3
        assert alert.source_ip == "10.0.0.50"

    def test_minimal_alert_payload(self):
        alert = AlertPayload(
            alert_id="TEST-001",
            rule_id=100,
            rule_description="test rule",
            alert_level=1,
            source_ip=None,
            dest_ip=None,
            agent_name="test-agent",
            timestamp="2026-06-25T00:00:00Z",
            raw_log="",
        )
        assert alert.alert_id == "TEST-001"
        assert alert.source_ip is None
        assert alert.dest_ip is None


class TestSOCAgentState:
    def _make_state(self, **overrides) -> SOCAgentState:
        default = {
            "alert": AlertPayload(
                alert_id="WAZUH-2001",
                rule_id=800200,
                rule_description="Suspicious outbound connection",
                alert_level=4,
                source_ip="192.168.1.100",
                dest_ip="203.0.113.50",
                agent_name="endpoint-01",
                timestamp="2026-06-25T14:00:00Z",
                raw_log="netstat: suspicious outbound TCP 203.0.113.50:443",
            ),
            "severity": "CRITICAL",
            "false_positive_probability": 0.05,
            "mitre_techniques": ["TA0006", "TA0010"],
            "attack_narrative": "Lateral movement detected",
            "affected_assets": ["192.168.1.100", "203.0.113.50"],
            "threat_actor_matches": [],
            "ioc_enrichment": {},
            "response_actions": [],
            "human_approved": False,
            "approval_timeout": False,
            "incident_id": "",
            "final_report": "",
            "messages": [],
        }
        default.update(overrides)
        return default

    def test_initial_state_defaults(self):
        state = self._make_state()
        assert state["severity"] == "CRITICAL"
        assert state["human_approved"] is False
        assert state["approval_timeout"] is False
        assert isinstance(state["mitre_techniques"], list)
        assert isinstance(state["messages"], list)

    def test_state_severity_values(self):
        for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            state = self._make_state(severity=severity)
            assert state["severity"] == severity

    def test_fp_probability_bounds(self):
        for prob in [0.0, 0.25, 0.5, 0.75, 0.95]:
            state = self._make_state(false_positive_probability=prob)
            assert 0.0 <= state["false_positive_probability"] <= 1.0

    def test_mitre_techniques_format(self):
        state = self._make_state(mitre_techniques=["TA0006", "TA0008", "T1059"])
        assert all(t.startswith(("TA", "T")) for t in state["mitre_techniques"])

    def test_empty_incident_id(self):
        state = self._make_state(incident_id="")
        assert state["incident_id"] == ""

    def test_incident_id_format(self):
        state = self._make_state(incident_id="INC-ABCDEF12")
        assert state["incident_id"].startswith("INC-")

    def test_response_actions_structure(self):
        actions = [
            {"action": "isolate_host", "target": "192.168.1.100", "status": "pending"},
            {"action": "block_ip", "target": "203.0.113.50", "status": "completed"},
        ]
        state = self._make_state(response_actions=actions)
        assert len(state["response_actions"]) == 2
        assert state["response_actions"][0]["action"] == "isolate_host"

    def test_human_approval_workflow(self):
        state_approved = self._make_state(human_approved=True, approval_timeout=False)
        assert state_approved["human_approved"] is True

        state_timeout = self._make_state(human_approved=False, approval_timeout=True)
        assert state_timeout["approval_timeout"] is True
        assert state_timeout["human_approved"] is False

    def test_messages_append_behavior(self):
        state1 = self._make_state(messages=["msg1"])
        state2 = self._make_state(messages=["msg2"])
        combined = state1["messages"] + state2["messages"]
        assert combined == ["msg1", "msg2"]
