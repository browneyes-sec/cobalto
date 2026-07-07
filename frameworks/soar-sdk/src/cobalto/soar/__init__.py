"""
Cobalto SOAR SDK
Framework for n8n workflow automation, SIEM alert normalization,
and playbook orchestration.
"""

from .workflow_builder import WorkflowBuilder, WorkflowNode, WorkflowEdge
from .webhook_handler import WebhookHandler, WebhookPayload
from .webhook_models import WazuhAlert, N8NWebhookPayload, NormalizedAlert
from .webhook_wazuh import normalize_wazuh_alert, build_alert_context
from .playbook import Playbook, PlaybookStep, PlaybookAction
from .integrations import (
    Integration,
    WazuhIntegration,
    TheHiveIntegration,
    SlackIntegration,
    CortexIntegration,
    OpenCTIIntegration,
)

__all__ = [
    # Workflow
    "WorkflowBuilder",
    "WorkflowNode",
    "WorkflowEdge",
    # Webhook handler
    "WebhookHandler",
    "WebhookPayload",
    # Webhook models (SIEM normalization)
    "WazuhAlert",
    "N8NWebhookPayload",
    "NormalizedAlert",
    "normalize_wazuh_alert",
    "build_alert_context",
    # Playbook
    "Playbook",
    "PlaybookStep",
    "PlaybookAction",
    # Integrations
    "Integration",
    "WazuhIntegration",
    "TheHiveIntegration",
    "SlackIntegration",
    "CortexIntegration",
    "OpenCTIIntegration",
]