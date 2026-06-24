"""
Cortex MCP Tools - Tools for interacting with Cortex analyzer/responder.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool


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
    """Get Cortex analyzers."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    params: Dict[str, Any] = {}
    if type:
        params["type"] = type

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.cortex_url}/api/analyzer",
            params=params,
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        response.raise_for_status()
        return response.json()


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
    """Get Cortex analyzer details."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.cortex_url}/api/analyzer/{analyzer_id}",
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        response.raise_for_status()
        return response.json()


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
    """Analyze observable with Cortex."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    payload = {
        "data": data,
        "dataType": data_type,
        "tlp": tlp,
        "message": message or f"Automated analysis via MCP",
    }

    async with httpx.AsyncClient(timeout=300) as client:
        # Create job
        response = await client.post(
            f"{settings.cortex_url}/api/analyzer/{analyzer_id}/run",
            json=payload,
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        response.raise_for_status()
        job = response.json()

        # Wait for job to complete
        job_id = job.get("id")
        if job_id:
            import asyncio
            for _ in range(60):  # Wait up to 5 minutes
                await asyncio.sleep(5)
                status_response = await client.get(
                    f"{settings.cortex_url}/api/job/{job_id}",
                    headers={"Authorization": f"Bearer {settings.cortex_token}"},
                )
                status = status_response.json()
                if status.get("status") in ["Waiting", "InProgress"]:
                    continue
                else:
                    return status

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
    """Get Cortex responders."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    params: Dict[str, Any] = {}
    if type:
        params["type"] = type

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.cortex_url}/api/responder",
            params=params,
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        response.raise_for_status()
        return response.json()


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
    """Execute Cortex responder."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    payload = {
        "objectType": object_type,
        "objectId": object_id,
    }

    async with httpx.AsyncClient(timeout=300) as client:
        response = await client.post(
            f"{settings.cortex_url}/api/responder/{responder_id}/run",
            json=payload,
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        response.raise_for_status()
        return response.json()


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
    """Get Cortex jobs."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    params: Dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.cortex_url}/api/job",
            params=params,
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        response.raise_for_status()
        return response.json()


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
    """Get Cortex job report."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.cortex_url}/api/job/{job_id}/waitreport?atMost=5s",
            headers={"Authorization": f"Bearer {settings.cortex_token}"},
        )
        response.raise_for_status()
        return response.json()
