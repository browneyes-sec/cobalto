"""
Cortex MCP Tools - Tools for interacting with Cortex analyzer/responder.
All requests use the pooled HTTP client with circuit breaker.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.transport.pool import execute_request, get_pool
import asyncio


async def _cortex_request(method: str, path: str, **kwargs) -> Any:
    from cobalto.core.config import get_settings
    settings = get_settings()
    return await execute_request(
        name="cortex",
        base_url=settings.cortex_url,
        method=method,
        path=path,
        headers={"Authorization": f"Bearer {settings.cortex_token}"},
        **kwargs,
    )


@mcp_tool(
    name="cortex_get_analyzers",
    description="Get list of available Cortex analyzers",
    input_schema={
        "type": "object",
        "properties": {
            "type": {"type": "string", "description": "Filter by type (file, ip, domain, url, hash)"},
        },
        "required": [],
    },
    tags=["cortex", "analyzers"],
)
async def cortex_get_analyzers(type: Optional[str] = None) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    if type:
        params["type"] = type
    return await _cortex_request("GET", "/api/analyzer", params=params)


@mcp_tool(
    name="cortex_get_analyzer",
    description="Get details of a specific analyzer",
    input_schema={
        "type": "object",
        "properties": {
            "analyzer_id": {"type": "string", "description": "Analyzer ID"},
        },
        "required": ["analyzer_id"],
    },
    tags=["cortex", "analyzers"],
)
async def cortex_get_analyzer(analyzer_id: str) -> Dict[str, Any]:
    return await _cortex_request("GET", f"/api/analyzer/{analyzer_id}")


@mcp_tool(
    name="cortex_analyze_observable",
    description="Analyze an observable using Cortex",
    input_schema={
        "type": "object",
        "properties": {
            "analyzer_id": {"type": "string", "description": "Analyzer ID to use"},
            "data": {"type": "string", "description": "Observable data (IP, domain, hash, etc.)"},
            "data_type": {"type": "string", "description": "Data type (ip, domain, hash, url, etc.)"},
            "tlp": {"type": "integer", "enum": [0, 1, 2, 3], "description": "TLP level", "default": 2},
            "message": {"type": "string", "description": "Analysis message"},
        },
        "required": ["analyzer_id", "data", "data_type"],
    },
    tags=["cortex", "analysis"],
    timeout_seconds=300,
)
async def cortex_analyze_observable(
    analyzer_id: str,
    data: str,
    data_type: str,
    tlp: int = 2,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    from cobalto.core.config import get_settings
    settings = get_settings()

    payload = {
        "data": data,
        "dataType": data_type,
        "tlp": tlp,
        "message": message or "Automated analysis via MCP",
    }

    result = await execute_request(
        name="cortex",
        base_url=settings.cortex_url,
        method="POST",
        path=f"/api/analyzer/{analyzer_id}/run",
        json=payload,
        headers={"Authorization": f"Bearer {settings.cortex_token}"},
        timeout=300,
    )
    job = result
    job_id = job.get("id")
    if job_id:
        pool = await get_pool()
        client = await pool.get_client(
            name="cortex",
            base_url=settings.cortex_url,
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        for _ in range(60):
            await asyncio.sleep(5)
            status_response = await client.get(f"/api/job/{job_id}")
            status = status_response.json()
            if status.get("status") in ["Waiting", "InProgress"]:
                continue
            await pool.record_success("cortex")
            return status
        await pool.record_success("cortex")
    return job


@mcp_tool(
    name="cortex_get_responders",
    description="Get list of available Cortex responders",
    input_schema={
        "type": "object",
        "properties": {
            "type": {"type": "string", "description": "Filter by type (case, alert, observable)"},
        },
        "required": [],
    },
    tags=["cortex", "responders"],
)
async def cortex_get_responders(type: Optional[str] = None) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    if type:
        params["type"] = type
    return await _cortex_request("GET", "/api/responder", params=params)


@mcp_tool(
    name="cortex_execute_responder",
    description="Execute a responder action via Cortex",
    input_schema={
        "type": "object",
        "properties": {
            "responder_id": {"type": "string", "description": "Responder ID"},
            "object_type": {"type": "string", "description": "Object type (case, alert, observable)"},
            "object_id": {"type": "string", "description": "Object ID to act on"},
        },
        "required": ["responder_id", "object_type", "object_id"],
    },
    tags=["cortex", "responders", "response"],
    requires_approval=True,
)
async def cortex_execute_responder(
    responder_id: str,
    object_type: str,
    object_id: str,
) -> Dict[str, Any]:
    payload = {"objectType": object_type, "objectId": object_id}
    return await _cortex_request("POST", f"/api/responder/{responder_id}/run", json=payload, timeout=300)


@mcp_tool(
    name="cortex_get_jobs",
    description="Get Cortex analysis jobs",
    input_schema={
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["Waiting", "InProgress", "Success", "Failure"]},
            "limit": {"type": "integer", "default": 20},
        },
        "required": [],
    },
    tags=["cortex", "jobs"],
)
async def cortex_get_jobs(
    status: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    return await _cortex_request("GET", "/api/job", params=params)


@mcp_tool(
    name="cortex_get_job_report",
    description="Get report for a specific Cortex job",
    input_schema={
        "type": "object",
        "properties": {
            "job_id": {"type": "string", "description": "Job ID"},
        },
        "required": ["job_id"],
    },
    tags=["cortex", "reports"],
)
async def cortex_get_job_report(job_id: str) -> Dict[str, Any]:
    return await _cortex_request("GET", f"/api/job/{job_id}/waitreport?atMost=5s")
