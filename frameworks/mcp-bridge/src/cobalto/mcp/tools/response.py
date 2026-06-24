"""
Response MCP Tools - Automated response actions.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool


@mcp_tool(
    name="isolate_host",
    description="Isolate a host from the network (Wazuh active response)",
    input_schema={
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Wazuh agent ID of the host"},
            "reason": {"type": "string", "description": "Reason for isolation"},
            "duration_minutes": {"type": "integer", "description": "Isolation duration", "default": 60},
        },
        "required": ["agent_id", "reason"],
    },
    tags=["response", "isolation", "wazuh"],
    requires_approval=True,
)
async def isolate_host(
    agent_id: str,
    reason: str,
    duration_minutes: int = 60,
) -> Dict[str, Any]:
    """Isolate host from network."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    payload = {
        "command": "netsh",
        "arguments": ["advfirewall", "set", "allprofiles", "state", "off"],
        "timeout": duration_minutes * 60,
    }

    async with httpx.AsyncClient(verify=settings.wazuh_verify_ssl) as client:
        response = await client.put(
            f"{settings.wazuh_url}/active-response/{agent_id}",
            json=payload,
            auth=(settings.wazuh_username, settings.wazuh_password),
        )
        response.raise_for_status()

        return {
            "success": True,
            "action": "isolate_host",
            "agent_id": agent_id,
            "duration_minutes": duration_minutes,
            "reason": reason,
            "message": f"Host {agent_id} isolated for {duration_minutes} minutes",
        }


@mcp_tool(
    name="disable_user_account",
    description="Disable a user account (Windows/Linux)",
    input_schema={
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Target agent ID"},
            "username": {"type": "string", "description": "Username to disable"},
            "os_type": {"type": "string", "enum": ["windows", "linux"], "description": "OS type"},
        },
        "required": ["agent_id", "username", "os_type"],
    },
    tags=["response", "account", "disable"],
    requires_approval=True,
)
async def disable_user_account(
    agent_id: str,
    username: str,
    os_type: str,
) -> Dict[str, Any]:
    """Disable a user account."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    if os_type == "windows":
        command = "net"
        arguments = ["user", username, "/active:no"]
    else:
        command = "passwd"
        arguments = ["-l", username]

    payload = {
        "command": command,
        "arguments": arguments,
    }

    async with httpx.AsyncClient(verify=settings.wazuh_verify_ssl) as client:
        response = await client.put(
            f"{settings.wazuh_url}/active-response/{agent_id}",
            json=payload,
            auth=(settings.wazuh_username, settings.wazuh_password),
        )
        response.raise_for_status()

        return {
            "success": True,
            "action": "disable_user_account",
            "agent_id": agent_id,
            "username": username,
            "os_type": os_type,
            "message": f"Account {username} disabled on {agent_id}",
        }


@mcp_tool(
    name="quarantine_file",
    description="Quarantine (move to隔离) a suspicious file",
    input_schema={
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Target agent ID"},
            "file_path": {"type": "string", "description": "Path to the file"},
            "quarantine_path": {"type": "string", "description": "Quarantine destination path"},
        },
        "required": ["agent_id", "file_path"],
    },
    tags=["response", "quarantine", "file"],
    requires_approval=True,
)
async def quarantine_file(
    agent_id: str,
    file_path: str,
    quarantine_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Quarantine a suspicious file."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    if not quarantine_path:
        quarantine_path = f"/quarantine/{file_path.replace('/', '_')}"

    payload = {
        "command": "mv",
        "arguments": [file_path, quarantine_path],
    }

    async with httpx.AsyncClient(verify=settings.wazuh_verify_ssl) as client:
        response = await client.put(
            f"{settings.wazuh_url}/active-response/{agent_id}",
            json=payload,
            auth=(settings.wazuh_username, settings.wazuh_password),
        )
        response.raise_for_status()

        return {
            "success": True,
            "action": "quarantine_file",
            "agent_id": agent_id,
            "file_path": file_path,
            "quarantine_path": quarantine_path,
            "message": f"File {file_path} quarantined",
        }


@mcp_tool(
    name="get_response_actions",
    description="Get available response actions",
    input_schema={
        "type": "object",
        "properties": {},
        "required": [],
    },
    tags=["response", "catalog"],
)
async def get_response_actions() -> Dict[str, Any]:
    """Get catalog of available response actions."""
    return {
        "actions": [
            {
                "name": "block_ip",
                "description": "Block an IP address via firewall",
                "category": "network",
                "requires_approval": True,
            },
            {
                "name": "isolate_host",
                "description": "Isolate host from network",
                "category": "network",
                "requires_approval": True,
            },
            {
                "name": "disable_user_account",
                "description": "Disable a user account",
                "category": "identity",
                "requires_approval": True,
            },
            {
                "name": "quarantine_file",
                "description": "Quarantine a suspicious file",
                "category": "endpoint",
                "requires_approval": True,
            },
            {
                "name": "kill_process",
                "description": "Kill a running process",
                "category": "endpoint",
                "requires_approval": True,
            },
            {
                "name": "collect_forensics",
                "description": "Collect forensic artifacts",
                "category": "investigation",
                "requires_approval": False,
            },
        ],
    }
