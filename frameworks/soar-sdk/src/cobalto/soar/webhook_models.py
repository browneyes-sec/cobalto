"""
Webhook models for alert ingestion from various SIEM/EDR sources.

These models define the wire format that n8n (or other middleware) delivers
to Cobalt's webhook endpoints. Each source gets its own payload model with
source-specific fields, plus a ``NormalizedAlert`` that represents the common
internal format.

Extracted from ``services/langgraph/main.py`` to place SIEM-specific schemas
in the SOAR SDK where they belong.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# Wazuh models
# =============================================================================

class WazuhAlert(BaseModel):
    """Wazuh alert delivered via n8n webhook.

    Matches the n8n-wrapped Wazuh alert structure. Each field corresponds
    to the standard Wazuh alert JSON keys decoded by n8n's Wazuh node.
    """
    rule_id: Optional[str] = None
    rule_level: Optional[int] = None
    rule_description: Optional[str] = None
    rule_groups: Optional[str] = None
    rule_mitre: Optional[Dict[str, Any]] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    srcip: Optional[str] = None
    dstip: Optional[str] = None
    srcport: Optional[int] = None
    dstport: Optional[int] = None
    protocol: Optional[str] = None
    log: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None
    full_log: Optional[str] = None
    location: Optional[str] = None


class N8NWebhookPayload(BaseModel):
    """Generic n8n webhook payload wrapper.

    n8n delivers alerts wrapped in this structure, with the actual alert
    content in the ``alert`` field (typed per-source via ``WazuhAlert``
    or equivalents for other integrations).
    """
    alert_id: str
    alert: WazuhAlert
    tenant_id: Optional[str] = None
    source: str = "wazuh"
    metadata: Optional[Dict[str, Any]] = None


# =============================================================================
# Normalized alert format (internal)
# =============================================================================

class NormalizedAlert(BaseModel):
    """Common alert format used internally by agents.

    All source-specific parsers (Wazuh, Sentinel, CrowdStrike, ...)
    produce this format so the supervisor and agents work with a unified
    schema regardless of the alert source.
    """
    id: str
    source: str
    timestamp: Optional[str] = None
    rule: Dict[str, Any] = Field(default_factory=lambda: {
        "id": None, "level": None, "description": None,
        "groups": None, "mitre": {},
    })
    agent: Dict[str, Any] = Field(default_factory=lambda: {
        "id": None, "name": None,
    })
    network: Dict[str, Any] = Field(default_factory=lambda: {
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "protocol": None,
    })
    raw: Dict[str, Any] = Field(default_factory=lambda: {
        "log": None, "data": None,
        "full_log": None, "location": None,
    })
    metadata: Dict[str, Any] = Field(default_factory=dict)
