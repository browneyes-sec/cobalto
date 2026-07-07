"""
Agent Collaboration MCP Tools - Tools for inter-agent communication.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.registry.resources import mcp_resource


@mcp_tool(
    name="agent_send_message",
    description="Send a message to another agent",
    input_schema={
        "type": "object",
        "properties": {
            "target_agent": {"type": "string", "description": "Target agent type or ID"},
            "message": {"type": "string", "description": "Message content"},
            "message_type": {
                "type": "string",
                "enum": ["request", "response", "notification", "escalation"],
                "description": "Message type",
                "default": "notification"
            },
            "priority": {
                "type": "string",
                "enum": ["low", "medium", "high", "urgent"],
                "description": "Message priority",
                "default": "medium"
            },
        },
        "required": ["target_agent", "message"],
    },
    tags=["agent", "collaboration", "messaging"],
)
async def agent_send_message(
    target_agent: str,
    message: str,
    message_type: str = "notification",
    priority: str = "medium",
) -> Dict[str, Any]:
    """Send message to another agent."""
    import uuid
    from datetime import datetime

    message_id = f"msg-{uuid.uuid4().hex[:8]}"

    return {
        "message_id": message_id,
        "target_agent": target_agent,
        "message_type": message_type,
        "priority": priority,
        "status": "sent",
        "timestamp": datetime.utcnow().isoformat(),
    }


@mcp_tool(
    name="agent_request_approval",
    description="Request approval for a response action",
    input_schema={
        "type": "object",
        "properties": {
            "action": {"type": "string", "description": "Action requiring approval"},
            "action_details": {"type": "object", "description": "Action details"},
            "reason": {"type": "string", "description": "Reason for the action"},
            "timeout_minutes": {"type": "integer", "description": "Approval timeout", "default": 30},
        },
        "required": ["action", "reason"],
    },
    tags=["agent", "approval", "response"],
)
async def agent_request_approval(
    action: str,
    reason: str,
    action_details: Optional[Dict[str, Any]] = None,
    timeout_minutes: int = 30,
) -> Dict[str, Any]:
    """Request approval for action."""
    import uuid
    from datetime import datetime

    approval_id = f"approval-{uuid.uuid4().hex[:8]}"

    return {
        "approval_id": approval_id,
        "action": action,
        "reason": reason,
        "action_details": action_details or {},
        "status": "pending",
        "timeout_minutes": timeout_minutes,
        "created_at": datetime.utcnow().isoformat(),
        "message": f"Approval requested for: {action}",
    }


@mcp_tool(
    name="agent_escalate",
    description="Escalate an alert to higher severity or senior analyst",
    input_schema={
        "type": "object",
        "properties": {
            "alert_id": {"type": "string", "description": "Alert ID to escalate"},
            "reason": {"type": "string", "description": "Escalation reason"},
            "target_severity": {
                "type": "string",
                "enum": ["high", "critical"],
                "description": "Target severity level"
            },
            "notify_channels": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Channels to notify (slack, email, pager)",
                "default": ["slack"]
            },
        },
        "required": ["alert_id", "reason"],
    },
    tags=["agent", "escalation"],
)
async def agent_escalate(
    alert_id: str,
    reason: str,
    target_severity: Optional[str] = None,
    notify_channels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Escalate alert."""
    import uuid
    from datetime import datetime

    escalation_id = f"esc-{uuid.uuid4().hex[:8]}"

    return {
        "escalation_id": escalation_id,
        "alert_id": alert_id,
        "reason": reason,
        "target_severity": target_severity,
        "notify_channels": notify_channels or ["slack"],
        "status": "escalated",
        "timestamp": datetime.utcnow().isoformat(),
    }


@mcp_tool(
    name="agent_get_capabilities",
    description="Get available agents and their capabilities",
    input_schema={
        "type": "object",
        "properties": {},
        "required": [],
    },
    tags=["agent", "capabilities"],
)
async def agent_get_capabilities() -> Dict[str, Any]:
    """Get agent capabilities."""
    agents = [
        {
            "agent_type": "triage",
            "name": "Triage Agent",
            "description": "Initial alert assessment and severity determination",
            "capabilities": ["alert_triage", "severity_assessment", "ioc_extraction"],
            "tools": ["wazuh_get_alerts", "wazuh_get_agents"],
        },
        {
            "agent_type": "analysis",
            "name": "Analysis Agent",
            "description": "Deep analysis of security incidents",
            "capabilities": ["deep_analysis", "attack_narrative", "mitre_mapping"],
            "tools": ["wazuh_get_alerts", "opencti_search_indicators", "mitre_map_alert"],
        },
        {
            "agent_type": "threat_intel",
            "name": "Threat Intel Agent",
            "description": "Threat intelligence lookup and enrichment",
            "capabilities": ["ioc_enrichment", "threat_actor_identification", "ttp_mapping"],
            "tools": ["opencti_search_indicators", "opencti_enrich_indicator", "opencti_get_mitre_attack"],
        },
        {
            "agent_type": "response",
            "name": "Response Agent",
            "description": "Automated response actions",
            "capabilities": ["containment", "isolation", "blocking", "quarantine"],
            "tools": ["wazuh_block_ip", "isolate_host", "disable_user_account", "quarantine_file"],
        },
        {
            "agent_type": "threat_hunt",
            "name": "Threat Hunt Agent",
            "description": "Proactive threat hunting",
            "capabilities": ["hypothesis_testing", "pattern_detection", "anomaly_hunting"],
            "tools": ["wazuh_get_alerts", "opencti_search_indicators"],
        },
        {
            "agent_type": "documentation",
            "name": "Documentation Agent",
            "description": "Incident documentation and reporting",
            "capabilities": ["report_generation", "evidence_collection", "timeline_reconstruction"],
            "tools": ["thehive_get_case", "thehive_add_comment"],
        },
    ]

    return {"agents": agents, "count": len(agents)}


@mcp_tool(
    name="agent_get_status",
    description="Get status of all agents",
    input_schema={
        "type": "object",
        "properties": {},
        "required": [],
    },
    tags=["agent", "status"],
)
async def agent_get_status() -> Dict[str, Any]:
    """Get agent status."""
    # In production, this would query actual agent metrics
    agents = [
        {"agent_type": "triage", "status": "idle", "queue_size": 0},
        {"agent_type": "analysis", "status": "idle", "queue_size": 0},
        {"agent_type": "threat_intel", "status": "idle", "queue_size": 0},
        {"agent_type": "response", "status": "idle", "queue_size": 0},
        {"agent_type": "threat_hunt", "status": "idle", "queue_size": 0},
        {"agent_type": "documentation", "status": "idle", "queue_size": 0},
    ]

    return {
        "agents": agents,
        "total_agents": len(agents),
        "active_agents": sum(1 for a in agents if a["status"] == "running"),
    }


@mcp_tool(
    name="agent_collaborate",
    description="Initiate collaborative analysis between agents",
    input_schema={
        "type": "object",
        "properties": {
            "alert_id": {"type": "string", "description": "Alert ID to collaborate on"},
            "agents": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Agents to include in collaboration"
            },
            "collaboration_type": {
                "type": "string",
                "enum": ["sequential", "parallel", "consensus"],
                "description": "Type of collaboration",
                "default": "sequential"
            },
        },
        "required": ["alert_id", "agents"],
    },
    tags=["agent", "collaboration"],
)
async def agent_collaborate(
    alert_id: str,
    agents: List[str],
    collaboration_type: str = "sequential",
) -> Dict[str, Any]:
    """Initiate agent collaboration."""
    import uuid
    from datetime import datetime

    collaboration_id = f"collab-{uuid.uuid4().hex[:8]}"

    return {
        "collaboration_id": collaboration_id,
        "alert_id": alert_id,
        "agents": agents,
        "collaboration_type": collaboration_type,
        "status": "initiated",
        "timestamp": datetime.utcnow().isoformat(),
    }


@mcp_resource(
    uri="agents://capabilities",
    name="Agent Capabilities",
    description="List of all agents and their capabilities",
    tags=["agents", "capabilities"],
)
async def agent_capabilities_resource(uri: str) -> Dict[str, Any]:
    """Get agent capabilities resource."""
    return await agent_get_capabilities()


@mcp_resource(
    uri="agents://status",
    name="Agent Status",
    description="Current status of all agents",
    tags=["agents", "status"],
)
async def agent_status_resource(uri: str) -> Dict[str, Any]:
    """Get agent status resource."""
    return await agent_get_status()
