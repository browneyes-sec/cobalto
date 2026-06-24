"""
Cobalto SOAR SDK
Framework for n8n workflow automation and playbook orchestration.
"""

from .workflow_builder import WorkflowBuilder, WorkflowNode, WorkflowEdge
from .webhook_handler import WebhookHandler, WebhookPayload
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
    "WorkflowBuilder",
    "WorkflowNode",
    "WorkflowEdge",
    "WebhookHandler",
    "WebhookPayload",
    "Playbook",
    "PlaybookStep",
    "PlaybookAction",
    "Integration",
    "WazuhIntegration",
    "TheHiveIntegration",
    "SlackIntegration",
    "CortexIntegration",
    "OpenCTIIntegration",
]