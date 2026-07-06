"""
Tests for Wazuh webhook normalization — extracted from main.py into
the SOAR SDK for independent unit testing.

These tests verify that ``normalize_wazuh_alert`` produces the exact same
output the inline code in ``main.py`` produced, ensuring zero behavioral
change during extraction.
"""

from __future__ import annotations

from typing import Any, Dict
from cobalto.soar.webhook_models import WazuhAlert, N8NWebhookPayload
from cobalto.soar.webhook_wazuh import normalize_wazuh_alert, build_alert_context


class TestNormalizeWazuhAlert:
    """Tests for the Wazuh alert normalization function."""

    def test_basic_alert(self) -> None:
        """Normalize a fully populated alert."""
        alert = WazuhAlert(
            rule_id="1001",
            rule_level=10,
            rule_description="Test alert",
            rule_groups="syslog,errors",
            rule_mitre={"tactic": "execution", "technique": {"id": "T1059"}},
            agent_id="001",
            agent_name="server-01",
            srcip="192.168.1.100",
            dstip="10.0.0.1",
            srcport=54321,
            dstport=80,
            protocol="TCP",
            timestamp="2024-01-15T10:30:00Z",
            log={"message": "test"},
            data={"field": "value"},
            full_log="full log line",
            location="/var/log/syslog",
        )
        payload = N8NWebhookPayload(
            alert_id="alert-001",
            alert=alert,
            tenant_id="acme",
            source="wazuh",
        )

        result = normalize_wazuh_alert(payload)

        assert result["id"] == "alert-001"
        assert result["source"] == "wazuh"
        assert result["timestamp"] == "2024-01-15T10:30:00Z"
        assert result["rule"]["id"] == "1001"
        assert result["rule"]["level"] == 10
        assert result["rule"]["description"] == "Test alert"
        assert result["rule"]["groups"] == "syslog,errors"
        assert result["rule"]["mitre"] == {"tactic": "execution", "technique": {"id": "T1059"}}
        assert result["agent"]["id"] == "001"
        assert result["agent"]["name"] == "server-01"
        assert result["network"]["src_ip"] == "192.168.1.100"
        assert result["network"]["dst_ip"] == "10.0.0.1"
        assert result["network"]["src_port"] == 54321
        assert result["network"]["dst_port"] == 80
        assert result["network"]["protocol"] == "TCP"
        assert result["raw"]["log"] == {"message": "test"}
        assert result["raw"]["data"] == {"field": "value"}
        assert result["raw"]["full_log"] == "full log line"
        assert result["raw"]["location"] == "/var/log/syslog"

    def test_minimal_alert(self) -> None:
        """Normalize an alert with only required fields."""
        alert = WazuhAlert(rule_id="1002")
        payload = N8NWebhookPayload(alert_id="alert-002", alert=alert)

        result = normalize_wazuh_alert(payload)

        assert result["id"] == "alert-002"
        assert result["rule"]["id"] == "1002"
        assert result["rule"]["level"] is None
        assert result["agent"]["id"] is None
        assert result["network"]["src_ip"] is None

    def test_empty_alert(self) -> None:
        """Normalize an alert with no fields set."""
        alert = WazuhAlert()
        payload = N8NWebhookPayload(alert_id="alert-empty", alert=alert)

        result = normalize_wazuh_alert(payload)

        assert result["id"] == "alert-empty"
        for key in ("rule", "agent", "network", "raw"):
            assert isinstance(result[key], dict)

    def test_preserves_raw_log_none(self) -> None:
        """When log data is None, raw.log remains None."""
        alert = WazuhAlert(rule_id="1003")
        payload = N8NWebhookPayload(alert_id="alert-003", alert=alert)
        result = normalize_wazuh_alert(payload)
        assert result["raw"]["log"] is None


class TestBuildAlertContext:
    """Tests for the alert context builder."""

    def test_default_tenant(self) -> None:
        """When tenant_id is None, fall back to 'default'."""
        alert = WazuhAlert(rule_id="2001")
        payload = N8NWebhookPayload(alert_id="alert-010", alert=alert)
        ctx = build_alert_context(payload)
        assert ctx["tenant_id"] == "default"

    def test_custom_tenant(self) -> None:
        """When tenant_id is set, it is preserved."""
        alert = WazuhAlert(rule_id="2002")
        payload = N8NWebhookPayload(
            alert_id="alert-011",
            alert=alert,
            tenant_id="acme-corp",
        )
        ctx = build_alert_context(payload)
        assert ctx["tenant_id"] == "acme-corp"

    def test_source_from_payload(self) -> None:
        """Source field reflects the payload's source."""
        alert = WazuhAlert(rule_id="2003")
        payload = N8NWebhookPayload(
            alert_id="alert-012",
            alert=alert,
            source="wazuh",
        )
        ctx = build_alert_context(payload)
        assert ctx["source"] == "wazuh"

    def test_metadata_propagation(self) -> None:
        """Extra metadata in the payload flows into the context."""
        alert = WazuhAlert(rule_id="2004")
        payload = N8NWebhookPayload(
            alert_id="alert-013",
            alert=alert,
            metadata={"correlation_id": "abc-123", "environment": "prod"},
        )
        ctx = build_alert_context(payload)
        assert ctx["metadata"]["correlation_id"] == "abc-123"
        assert ctx["metadata"]["environment"] == "prod"

    def test_empty_metadata(self) -> None:
        """When metadata is None, context gets an empty dict."""
        alert = WazuhAlert(rule_id="2005")
        payload = N8NWebhookPayload(alert_id="alert-014", alert=alert)
        ctx = build_alert_context(payload)
        assert ctx["metadata"] == {}
