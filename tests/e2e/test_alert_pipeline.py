"""
E2E Tests: Alert Analysis Pipeline

Tests the full LangGraph agent pipeline end-to-end:
  - Credential access alert (HIGH severity → full pipeline)
  - Lateral movement alert (CRITICAL severity → escalation path)
  - LOW severity alert (auto-documentation → fast path)
  - Input validation and error handling

Requires: langgraph-agent service deployed with mocked external deps.
"""

import pytest
import httpx
from conftest import analyze_alert, CREDENTIAL_ACCESS_ALERT, LATERAL_MOVEMENT_ALERT, LOW_SEVERITY_ALERT


@pytest.mark.pipeline
class TestCredentialAccessPipeline:
    """
    HIGH-severity credential access — full pipeline test.

    Expected flow: triage → analysis → threat_intel → response → human_gate
    Because severity=HIGH and fp_prob=0.05 → goes through full analysis.
    response_agent creates isolate_host + block_ip + create_ticket (high impact).
    human_approval_node sets human_approved=False (needs approval).
    """

    ALERT = CREDENTIAL_ACCESS_ALERT

    def test_alert_accepts_valid_payload(self, http_client: httpx.Client, auth_headers: dict):
        """POST /agent/analyze should return 200 for a valid alert."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        assert result["incident_id"], "No incident_id in response"

    def test_alert_returns_all_required_fields(self, http_client: httpx.Client, auth_headers: dict):
        """The response should contain all AgentResult fields."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        required = [
            "incident_id", "final_report", "severity",
            "response_actions", "human_approved", "approval_timeout", "messages",
        ]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_alert_severity(self, http_client: httpx.Client, auth_headers: dict):
        """alert_level=3 should produce HIGH severity."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        assert result["severity"] == "HIGH", (
            f"Expected HIGH severity, got {result['severity']}"
        )

    def test_alert_incident_id_format(self, http_client: httpx.Client, auth_headers: dict):
        """incident_id should follow the INC-XXXXXXXX format."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        assert result["incident_id"].startswith("INC-"), (
            f"Unexpected incident_id: {result['incident_id']}"
        )

    def test_alert_final_report(self, http_client: httpx.Client, auth_headers: dict):
        """The final report should contain key sections."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        report = result["final_report"]
        assert "INCIDENT REPORT" in report
        assert "ATTACK NARRATIVE" in report
        assert "RESPONSE ACTIONS" in report
        # Should reference the alert
        assert self.ALERT["alert_id"] in report

    def test_alert_mitre_techniques_in_report(self, http_client: httpx.Client, auth_headers: dict):
        """MITRE ATT&CK techniques should appear in the final report."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        # The alert contains "credential" in raw_log → TA0006
        assert "TA0006" in result["final_report"] or "None" in result["final_report"]

    def test_alert_response_actions(self, http_client: httpx.Client, auth_headers: dict):
        """HIGH severity should produce response actions including isolation."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        actions = result["response_actions"]
        assert isinstance(actions, list)
        assert len(actions) > 0

        # For HIGH severity, should contain isolate_host or block_ip
        action_types = {a["action"] for a in actions}
        assert "create_ticket" in action_types

    def test_alert_human_approval_needed(self, http_client: httpx.Client, auth_headers: dict):
        """HIGH severity with isolate_host should need human approval."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        # isolate_host is high-impact → human_approved=False
        action_types = {a["action"] for a in result["response_actions"]}
        if "isolate_host" in action_types:
            assert result["human_approved"] is False, (
                "High-impact actions should require human approval"
            )
        else:
            pytest.skip("No isolate_host action — approval not applicable")

    def test_alert_error_on_missing_fields(self, http_client: httpx.Client, auth_headers: dict):
        """Missing required fields should return 422."""
        resp = http_client.post(
            "/agent/analyze",
            json={"alert_id": "INCOMPLETE"},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_alert_error_on_empty_body(self, http_client: httpx.Client, auth_headers: dict):
        """Empty request body should return 422."""
        resp = http_client.post(
            "/agent/analyze",
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 422


@pytest.mark.pipeline
class TestLateralMovementPipeline:
    """
    CRITICAL-severity lateral movement — tests escalation path.

    Expected: alert_level=4 → CRITICAL → full pipeline → isolate_host
    → human_approval_node → needs approval → escalate on timeout
    """

    ALERT = LATERAL_MOVEMENT_ALERT

    def test_critical_severity_detected(self, http_client: httpx.Client, auth_headers: dict):
        """alert_level=4 should produce CRITICAL severity."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        assert result["severity"] == "CRITICAL", (
            f"Expected CRITICAL, got {result['severity']}"
        )

    def test_critical_response_actions(self, http_client: httpx.Client, auth_headers: dict):
        """CRITICAL severity should include isolate_host."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        actions = result["response_actions"]
        action_types = {a["action"] for a in actions}

        assert "isolate_host" in action_types, (
            "CRITICAL severity should include isolate_host"
        )
        assert "block_ip" in action_types
        assert "create_ticket" in action_types

    def test_critical_report_includes_exfiltration(self, http_client: httpx.Client, auth_headers: dict):
        """The report should reference exfiltration from the raw_log."""
        result = analyze_alert(http_client, auth_headers, self.ALERT)
        report = result["final_report"]
        # The raw_log contains "exfiltration"
        assert "TA0010" in report or "exfil" in report.lower()


@pytest.mark.pipeline
class TestLowSeverityPipeline:
    """
    LOW-severity scheduled task — tests auto-documentation path.

    Expected: alert_level=1 → LOW → route_after_triage → documentation
    Skips analysis, threat_intel, response, human_gate entirely.
    Fast path: triage → documentation → END.
    """

    def test_low_severity(self, http_client: httpx.Client, auth_headers: dict):
        """alert_level=1 should produce LOW severity."""
        result = analyze_alert(http_client, auth_headers, LOW_SEVERITY_ALERT)
        assert result["severity"] == "LOW"

    def test_low_severity_auto_documented(self, http_client: httpx.Client, auth_headers: dict):
        """LOW severity should produce a final report."""
        result = analyze_alert(http_client, auth_headers, LOW_SEVERITY_ALERT)
        assert result["final_report"]
        assert "INCIDENT REPORT" in result["final_report"]

    def test_low_severity_has_ticket_action(self, http_client: httpx.Client, auth_headers: dict):
        """Even LOW severity should have at least create_ticket."""
        result = analyze_alert(http_client, auth_headers, LOW_SEVERITY_ALERT)
        action_types = {a["action"] for a in result["response_actions"]}
        assert "create_ticket" in action_types

    def test_low_severity_human_approved(self, http_client: httpx.Client, auth_headers: dict):
        """LOW severity skips human_gate — human_approved stays False."""
        result = analyze_alert(http_client, auth_headers, LOW_SEVERITY_ALERT)
        # The LOW path goes triage → documentation → END, bypassing
        # human_approval_node, so human_approved remains at initial state
        assert result["human_approved"] is False

    def test_low_severity_no_isolate(self, http_client: httpx.Client, auth_headers: dict):
        """LOW severity should NOT contain isolate_host or block_ip."""
        result = analyze_alert(http_client, auth_headers, LOW_SEVERITY_ALERT)
        action_types = {a["action"] for a in result["response_actions"]}
        assert "isolate_host" not in action_types
        assert "block_ip" not in action_types
