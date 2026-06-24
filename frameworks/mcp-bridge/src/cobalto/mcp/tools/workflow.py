"""
Workflow Orchestration MCP Tools - Tools for managing agent workflows.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.registry.resources import mcp_resource


@mcp_tool(
    name="workflow_create",
    description="Create a new agent workflow",
    input_schema={
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Workflow name"},
            "description": {"type": "string", "description": "Workflow description"},
            "agents": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of agent types to include (triage, analysis, threat_intel, response)"
            },
            "trigger": {
                "type": "string",
                "enum": ["manual", "alert", "schedule"],
                "description": "Workflow trigger type",
                "default": "manual"
            },
        },
        "required": ["name", "agents"],
    },
    tags=["workflow", "orchestration"],
)
async def workflow_create(
    name: str,
    agents: List[str],
    description: Optional[str] = None,
    trigger: str = "manual",
) -> Dict[str, Any]:
    """Create a new workflow."""
    import uuid
    from datetime import datetime

    workflow_id = f"wf-{uuid.uuid4().hex[:8]}"

    # Define agent sequence
    agent_sequence = []
    for agent_type in agents:
        agent_sequence.append({
            "agent_type": agent_type,
            "status": "pending",
            "order": len(agent_sequence) + 1,
        })

    return {
        "workflow_id": workflow_id,
        "name": name,
        "description": description or f"Workflow with {len(agents)} agents",
        "agents": agent_sequence,
        "trigger": trigger,
        "status": "created",
        "created_at": datetime.utcnow().isoformat(),
    }


@mcp_tool(
    name="workflow_execute",
    description="Execute a workflow with input data",
    input_schema={
        "type": "object",
        "properties": {
            "workflow_id": {"type": "string", "description": "Workflow ID"},
            "input_data": {"type": "object", "description": "Input data for the workflow"},
            "agent_type": {
                "type": "string",
                "enum": ["triage", "analysis", "threat_intel", "response"],
                "description": "Specific agent to run (optional)"
            },
        },
        "required": ["input_data"],
    },
    tags=["workflow", "orchestration", "execution"],
)
async def workflow_execute(
    input_data: Dict[str, Any],
    workflow_id: Optional[str] = None,
    agent_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a workflow."""
    import uuid
    import time

    execution_id = f"exec-{uuid.uuid4().hex[:8]}"
    start_time = time.time()

    # If specific agent requested, run just that agent
    if agent_type:
        try:
            if agent_type == "triage":
                from services.langgraph.agents.triage import TriageAgent
                agent = TriageAgent()
            elif agent_type == "analysis":
                from services.langgraph.agents.analysis import AnalysisAgent
                agent = AnalysisAgent()
            elif agent_type == "threat_intel":
                from services.langgraph.agents.threat_intel import ThreatIntelAgent
                agent = ThreatIntelAgent()
            elif agent_type == "response":
                from services.langgraph.agents.response import ResponseAgent
                agent = ResponseAgent()
            else:
                return {"error": f"Unknown agent type: {agent_type}"}

            result = await agent.run(input_data)
            duration_ms = (time.time() - start_time) * 1000

            return {
                "execution_id": execution_id,
                "workflow_id": workflow_id,
                "agent_type": agent_type,
                "status": "completed",
                "result": result.output,
                "duration_ms": duration_ms,
            }

        except Exception as e:
            return {
                "execution_id": execution_id,
                "workflow_id": workflow_id,
                "agent_type": agent_type,
                "status": "failed",
                "error": str(e),
            }

    # Run full workflow (triage -> analysis -> threat_intel -> response)
    workflow_results = []
    agents_to_run = ["triage", "analysis", "threat_intel", "response"]

    for agent_name in agents_to_run:
        try:
            if agent_name == "triage":
                from services.langgraph.agents.triage import TriageAgent
                agent = TriageAgent()
            elif agent_name == "analysis":
                from services.langgraph.agents.analysis import AnalysisAgent
                agent = AnalysisAgent()
            elif agent_name == "threat_intel":
                from services.langgraph.agents.threat_intel import ThreatIntelAgent
                agent = ThreatIntelAgent()
            elif agent_name == "response":
                from services.langgraph.agents.response import ResponseAgent
                agent = ResponseAgent()
            else:
                continue

            result = await agent.run(input_data)
            workflow_results.append({
                "agent_type": agent_name,
                "status": "completed",
                "output": result.output,
            })

        except Exception as e:
            workflow_results.append({
                "agent_type": agent_name,
                "status": "failed",
                "error": str(e),
            })

    duration_ms = (time.time() - start_time) * 1000

    return {
        "execution_id": execution_id,
        "workflow_id": workflow_id,
        "status": "completed",
        "agents_executed": len(workflow_results),
        "results": workflow_results,
        "duration_ms": duration_ms,
    }


@mcp_tool(
    name="workflow_get_status",
    description="Get workflow execution status",
    input_schema={
        "type": "object",
        "properties": {
            "execution_id": {"type": "string", "description": "Execution ID"},
        },
        "required": ["execution_id"],
    },
    tags=["workflow", "status"],
)
async def workflow_get_status(execution_id: str) -> Dict[str, Any]:
    """Get workflow status."""
    # In production, this would query a database
    return {
        "execution_id": execution_id,
        "status": "completed",
        "message": "Workflow execution status retrieved",
    }


@mcp_tool(
    name="workflow_list",
    description="List available workflows",
    input_schema={
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["active", "inactive", "all"], "default": "all"},
        },
        "required": [],
    },
    tags=["workflow", "list"],
)
async def workflow_list(status: str = "all") -> Dict[str, Any]:
    """List workflows."""
    # Predefined workflows
    workflows = [
        {
            "workflow_id": "wf-alert-triage",
            "name": "Alert Triage",
            "description": "Basic alert triage and severity assessment",
            "agents": ["triage"],
            "trigger": "alert",
        },
        {
            "workflow_id": "wf-full-investigation",
            "name": "Full Investigation",
            "description": "Complete investigation with analysis and threat intel",
            "agents": ["triage", "analysis", "threat_intel"],
            "trigger": "manual",
        },
        {
            "workflow_id": "wf-incident-response",
            "name": "Incident Response",
            "description": "Full incident response workflow",
            "agents": ["triage", "analysis", "threat_intel", "response"],
            "trigger": "alert",
        },
        {
            "workflow_id": "wf-threat-hunt",
            "name": "Threat Hunt",
            "description": "Proactive threat hunting workflow",
            "agents": ["analysis", "threat_intel"],
            "trigger": "schedule",
        },
    ]

    return {
        "workflows": workflows,
        "count": len(workflows),
    }


@mcp_tool(
    name="workflow_cancel",
    description="Cancel a running workflow",
    input_schema={
        "type": "object",
        "properties": {
            "execution_id": {"type": "string", "description": "Execution ID to cancel"},
            "reason": {"type": "string", "description": "Reason for cancellation"},
        },
        "required": ["execution_id"],
    },
    tags=["workflow", "cancellation"],
    requires_approval=True,
)
async def workflow_cancel(
    execution_id: str,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Cancel a workflow execution."""
    return {
        "execution_id": execution_id,
        "status": "cancelled",
        "reason": reason or "Cancelled by user",
    }


@mcp_resource(
    uri="workflows://list",
    name="Available Workflows",
    description="List of all available workflows",
    tags=["workflows"],
)
async def workflow_list_resource(uri: str) -> Dict[str, Any]:
    """Get workflows resource."""
    result = await workflow_list()
    return result
