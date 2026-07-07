"""
Wazuh webhook normalization — converts n8n-wrapped Wazuh alerts into the
internal ``NormalizedAlert`` format used by agents.

Extracted from ``services/langgraph/main.py`` to place SIEM normalization
logic in the SOAR SDK where it can be unit-tested and reused independently
of the FastAPI routing layer.

Usage::

    from cobalto.soar.webhook_wazuh import normalize_wazuh_alert
    from cobalto.soar.webhook_models import N8NWebhookPayload

    normalized = normalize_wazuh_alert(payload)
    # → {
    #     "id": "...",
    #     "source": "wazuh",
    #     "rule": {"id": "...", "level": ..., ...},
    #     "agent": {"id": "...", "name": "..."},
    #     "network": {"src_ip": "...", ...},
    #     "raw": {"log": ..., ...},
    # }
"""

from __future__ import annotations

from typing import Any, Dict
from cobalto.soar.webhook_models import N8NWebhookPayload


def normalize_wazuh_alert(payload: N8NWebhookPayload) -> Dict[str, Any]:
    """Convert an n8n-wrapped Wazuh alert into the internal normalized format.

    Args:
        payload: The webhook payload as received from n8n.

    Returns:
        A dictionary in the ``NormalizedAlert`` shape consumed by the
        supervisor and downstream agents.
    """
    alert = payload.alert

    return {
        "id": payload.alert_id,
        "source": "wazuh",
        "timestamp": alert.timestamp,
        "rule": {
            "id": alert.rule_id,
            "level": alert.rule_level,
            "description": alert.rule_description,
            "groups": alert.rule_groups,
            "mitre": alert.rule_mitre,
        },
        "agent": {
            "id": alert.agent_id,
            "name": alert.agent_name,
        },
        "network": {
            "src_ip": alert.srcip,
            "dst_ip": alert.dstip,
            "src_port": alert.srcport,
            "dst_port": alert.dstport,
            "protocol": alert.protocol,
        },
        "raw": {
            "log": alert.log,
            "data": alert.data,
            "full_log": alert.full_log,
            "location": alert.location,
        },
    }


def build_alert_context(
    payload: N8NWebhookPayload,
) -> Dict[str, Any]:
    """Build the context dict that accompanies a normalized alert.

    Args:
        payload: The original webhook payload.

    Returns:
        Context dictionary with tenant_id, source, and metadata.
    """
    return {
        "tenant_id": payload.tenant_id or "default",
        "source": payload.source,
        "metadata": payload.metadata or {},
    }
