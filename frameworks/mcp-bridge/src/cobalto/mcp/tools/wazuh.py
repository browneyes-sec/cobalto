"""
Wazuh MCP Tools - Tools for interacting with Wazuh SIEM.
All requests use the pooled HTTP client with circuit breaker.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.transport.pool import execute_request


async def _wazuh_request(method: str, path: str, **kwargs) -> Any:
    from cobalto.core.config import get_settings
    settings = get_settings()
    return await execute_request(
        name="wazuh",
        base_url=settings.wazuh_url,
        method=method,
        path=path,
        auth=(settings.wazuh_username, settings.wazuh_password),
        verify=settings.wazuh_verify_ssl,
        **kwargs,
    )


@mcp_tool(
    name="wazuh_get_alerts",
    description="Get alerts from Wazuh with optional filters",
    input_schema={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "Maximum number of alerts", "default": 100},
            "offset": {"type": "integer", "description": "Offset for pagination", "default": 0},
            "level": {"type": "integer", "description": "Minimum alert level (1-15)"},
            "group": {"type": "string", "description": "Alert group filter"},
            "agent_id": {"type": "string", "description": "Agent ID filter"},
            "rule_id": {"type": "string", "description": "Rule ID filter"},
            "start_time": {"type": "string", "description": "Start time (ISO format)"},
            "end_time": {"type": "string", "description": "End time (ISO format)"},
        },
        "required": [],
    },
    tags=["wazuh", "siem", "alerts"],
)
async def wazuh_get_alerts(
    limit: int = 100,
    offset: int = 0,
    level: Optional[int] = None,
    group: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    if level is not None:
        params["level"] = level
    if group:
        params["group"] = group
    if agent_id:
        params["agent_id"] = agent_id
    if rule_id:
        params["rule_id"] = rule_id
    if start_time:
        params["start_time"] = start_time
    if end_time:
        params["end_time"] = end_time
    return await _wazuh_request("GET", "/alerts", params=params)


@mcp_tool(
    name="wazuh_get_agents",
    description="Get list of Wazuh agents",
    input_schema={
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["active", "pending", "disconnected", "never_connected"]},
            "limit": {"type": "integer", "default": 500},
        },
        "required": [],
    },
    tags=["wazuh", "agents"],
)
async def wazuh_get_agents(
    status: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    return await _wazuh_request("GET", "/agents", params=params)


@mcp_tool(
    name="wazuh_get_agent_info",
    description="Get detailed information about a specific Wazuh agent",
    input_schema={
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent ID"},
        },
        "required": ["agent_id"],
    },
    tags=["wazuh", "agents"],
)
async def wazuh_get_agent_info(agent_id: str) -> Dict[str, Any]:
    return await _wazuh_request("GET", f"/agents/{agent_id}")


@mcp_tool(
    name="wazuh_active_response",
    description="Execute an active response action via Wazuh",
    input_schema={
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Target agent ID"},
            "command": {"type": "string", "description": "Command to execute"},
            "arguments": {"type": "array", "items": {"type": "string"}, "description": "Command arguments"},
        },
        "required": ["agent_id", "command"],
    },
    tags=["wazuh", "response", "active-response"],
    requires_approval=True,
)
async def wazuh_active_response(
    agent_id: str,
    command: str,
    arguments: Optional[List[str]] = None,
) -> Dict[str, Any]:
    await _wazuh_request(
        "PUT",
        f"/active-response/{agent_id}",
        json={"command": command, "arguments": arguments or []},
    )
    return {"success": True, "message": f"Active response executed on agent {agent_id}"}


@mcp_tool(
    name="wazuh_block_ip",
    description="Block an IP address using Wazuh active response",
    input_schema={
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Target agent ID"},
            "ip": {"type": "string", "description": "IP address to block"},
            "timeout": {"type": "integer", "description": "Block duration in seconds", "default": 1800},
        },
        "required": ["agent_id", "ip"],
    },
    tags=["wazuh", "response", "firewall"],
    requires_approval=True,
)
async def wazuh_block_ip(
    agent_id: str,
    ip: str,
    timeout: int = 1800,
) -> Dict[str, Any]:
    await _wazuh_request(
        "PUT",
        f"/active-response/{agent_id}",
        json={"command": "firewall-drop", "arguments": ["-a", "add", "-s", ip], "timeout": timeout},
    )
    return {"success": True, "message": f"IP {ip} blocked on agent {agent_id}", "timeout": timeout}


@mcp_tool(
    name="wazuh_get_rules",
    description="Get Wazuh rules with optional filters",
    input_schema={
        "type": "object",
        "properties": {
            "group": {"type": "string", "description": "Rule group filter"},
            "limit": {"type": "integer", "default": 100},
        },
        "required": [],
    },
    tags=["wazuh", "rules"],
)
async def wazuh_get_rules(
    group: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": limit}
    if group:
        params["group"] = group
    return await _wazuh_request("GET", "/rules", params=params)
