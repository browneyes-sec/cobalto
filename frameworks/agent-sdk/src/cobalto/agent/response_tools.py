"""
Response Agent Tools

Tools for incident response:
- N8N Execute: Execute n8n workflow
- Wazuh Active Response: Execute active response on endpoints
- Firewall Block: Block IP via firewall API
- Slack Notify: Send notifications via Slack
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool
import structlog

logger = structlog.get_logger(__name__)


class N8NExecuteInput(BaseModel):
    """Input for n8n workflow execution."""
    workflow_id: str = Field(description="n8n workflow ID to execute")
    payload: Dict[str, Any] = Field(default={}, description="Workflow payload")


@tool(args_schema=N8NExecuteInput)
async def n8n_execute(workflow_id: str, payload: Dict[str, Any] = {}) -> str:
    """
    Execute an n8n workflow.

    Args:
        workflow_id: n8n workflow ID to execute
        payload: Workflow payload

    Returns:
        Execution result
    """
    try:
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"http://localhost:5678/api/v1/workflows/{workflow_id}/execute",
                headers={
                    "X-N8N-API-KEY": "change-me",
                    "Content-Type": "application/json",
                },
                json={"payload": payload},
                timeout=30.0,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    "n8n_execute_complete",
                    workflow_id=workflow_id,
                )
                return str(result)
            else:
                logger.error("n8n_execute_failed", status_code=response.status_code)
                return str({"error": f"n8n returned {response.status_code}"})

    except Exception as e:
        logger.error("n8n_execute_failed", error=str(e))
        return str({"error": str(e)})


class WazuhActiveResponseInput(BaseModel):
    """Input for Wazuh active response."""
    agent_id: str = Field(description="Wazuh agent ID")
    command: str = Field(description="Command to execute (e.g., firewall-drop)")
    arguments: List[str] = Field(default=[], description="Command arguments")


@tool(args_schema=WazuhActiveResponseInput)
async def wazuh_active_response(agent_id: str, command: str, arguments: List[str] = []) -> str:
    """
    Execute active response on a Wazuh agent.

    Args:
        agent_id: Wazuh agent ID
        command: Command to execute (e.g., firewall-drop)
        arguments: Command arguments

    Returns:
        Execution result
    """
    try:
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"https://localhost:55000/active-response/{agent_id}",
                auth=("wazuh", "admin"),
                verify=False,
                json={
                    "command": command,
                    "arguments": arguments,
                },
                timeout=30.0,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    "wazuh_active_response_complete",
                    agent_id=agent_id,
                    command=command,
                )
                return str(result)
            else:
                logger.error("wazuh_active_response_failed", status_code=response.status_code)
                return str({"error": f"Wazuh returned {response.status_code}"})

    except Exception as e:
        logger.error("wazuh_active_response_failed", error=str(e))
        return str({"error": str(e)})


class FirewallBlockInput(BaseModel):
    """Input for firewall block."""
    ip_address: str = Field(description="IP address to block")
    duration: int = Field(default=3600, description="Block duration in seconds")
    reason: str = Field(default="Security incident", description="Block reason")


@tool(args_schema=FirewallBlockInput)
async def firewall_block(ip_address: str, duration: int = 3600, reason: str = "Security incident") -> str:
    """
    Block an IP address via firewall.

    Args:
        ip_address: IP address to block
        duration: Block duration in seconds (default: 1 hour)
        reason: Block reason

    Returns:
        Block confirmation
    """
    try:
        # TODO: Integrate with actual firewall API (AWS Security Group, iptables, etc.)
        # For now, return placeholder
        logger.info(
            "firewall_block_placeholder",
            ip_address=ip_address,
            duration=duration,
            reason=reason,
        )

        return str({
            "action": "block",
            "ip_address": ip_address,
            "duration": duration,
            "reason": reason,
            "status": "placeholder",
            "message": "Firewall API integration required",
        })

    except Exception as e:
        logger.error("firewall_block_failed", error=str(e))
        return str({"error": str(e)})


class SlackNotifyInput(BaseModel):
    """Input for Slack notification."""
    channel: str = Field(default="#soc-alerts", description="Slack channel")
    message: str = Field(description="Notification message")
    severity: str = Field(default="info", description="Severity: info, warning, critical")


@tool(args_schema=SlackNotifyInput)
async def slack_notify(channel: str, message: str, severity: str = "info") -> str:
    """
    Send a Slack notification.

    Args:
        channel: Slack channel (default: #soc-alerts)
        message: Notification message
        severity: Severity level (info, warning, critical)

    Returns:
        Send confirmation
    """
    try:
        import httpx

        # Build Slack message with formatting
        emoji = {
            "info": "ℹ️",
            "warning": "⚠️",
            "critical": "🚨",
        }.get(severity, "ℹ️")

        formatted_message = f"{emoji} [{severity.upper()}] {message}"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": "Bearer xoxb-your-token",
                    "Content-Type": "application/json",
                },
                json={
                    "channel": channel,
                    "text": formatted_message,
                },
                timeout=10.0,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    "slack_notify_complete",
                    channel=channel,
                    severity=severity,
                )
                return str(result)
            else:
                logger.error("slack_notify_failed", status_code=response.status_code)
                return str({"error": f"Slack returned {response.status_code}"})

    except Exception as e:
        logger.error("slack_notify_failed", error=str(e))
        return str({"error": str(e)})
