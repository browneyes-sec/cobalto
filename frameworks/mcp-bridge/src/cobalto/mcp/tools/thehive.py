"""
TheHive MCP Tools - Tools for interacting with TheHive SOAR platform.
All requests use the pooled HTTP client with circuit breaker.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.transport.pool import execute_request


async def _thehive_request(method: str, path: str, **kwargs) -> Any:
    from cobalto.core.config import get_settings
    settings = get_settings()
    return await execute_request(
        name="thehive",
        base_url=settings.thehive_url,
        method=method,
        path=path,
        headers={"Authorization": f"Bearer {settings.thehive_token}"},
        **kwargs,
    )


@mcp_tool(
    name="thehive_create_case",
    description="Create a new case in TheHive",
    input_schema={
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Case title"},
            "description": {"type": "string", "description": "Case description"},
            "severity": {"type": "integer", "enum": [1, 2, 3], "description": "1=Low, 2=Medium, 3=High"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Case tags"},
            "tlp": {"type": "integer", "enum": [0, 1, 2, 3], "description": "TLP level"},
        },
        "required": ["title"],
    },
    tags=["thehive", "cases"],
)
async def thehive_create_case(
    title: str,
    description: Optional[str] = None,
    severity: int = 2,
    tags: Optional[List[str]] = None,
    tlp: int = 2,
) -> Dict[str, Any]:
    payload = {
        "title": title,
        "description": description or "",
        "severity": severity,
        "tags": tags or [],
        "tlp": tlp,
    }
    return await _thehive_request("POST", "/case", json=payload)


@mcp_tool(
    name="thehive_get_cases",
    description="Get cases from TheHive with optional filters",
    input_schema={
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["open", "resolved", "deleted"]},
            "severity": {"type": "integer", "enum": [1, 2, 3]},
            "limit": {"type": "integer", "default": 50},
        },
        "required": [],
    },
    tags=["thehive", "cases"],
)
async def thehive_get_cases(
    status: Optional[str] = None,
    severity: Optional[int] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity
    return await _thehive_request("GET", "/case", params=params)


@mcp_tool(
    name="thehive_get_case",
    description="Get a specific case from TheHive",
    input_schema={
        "type": "object",
        "properties": {
            "case_id": {"type": "string", "description": "Case ID"},
        },
        "required": ["case_id"],
    },
    tags=["thehive", "cases"],
)
async def thehive_get_case(case_id: str) -> Dict[str, Any]:
    return await _thehive_request("GET", f"/case/{case_id}")


@mcp_tool(
    name="thehive_add_observable",
    description="Add an observable (IOC) to a case",
    input_schema={
        "type": "object",
        "properties": {
            "case_id": {"type": "string", "description": "Case ID"},
            "data": {"type": "string", "description": "Observable value (IP, domain, hash, etc.)"},
            "data_type": {"type": "string", "description": "Type (ip, domain, hash, url, etc.)"},
            "tlp": {"type": "integer", "enum": [0, 1, 2, 3], "description": "TLP level"},
            "tags": {"type": "array", "items": {"type": "string"}},
            "message": {"type": "string", "description": "Description message"},
        },
        "required": ["case_id", "data", "data_type"],
    },
    tags=["thehive", "observables", "ioc"],
)
async def thehive_add_observable(
    case_id: str,
    data: str,
    data_type: str,
    tlp: int = 2,
    tags: Optional[List[str]] = None,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    payload = {
        "data": data,
        "dataType": data_type,
        "tlp": tlp,
        "tags": tags or [],
        "message": message or "",
    }
    return await _thehive_request("POST", f"/case/{case_id}/observable", json=payload)


@mcp_tool(
    name="thehive_add_task",
    description="Add a task to a case",
    input_schema={
        "type": "object",
        "properties": {
            "case_id": {"type": "string", "description": "Case ID"},
            "title": {"type": "string", "description": "Task title"},
            "description": {"type": "string", "description": "Task description"},
            "status": {"type": "string", "enum": ["waiting", "inprogress", "completed"]},
            "assignee": {"type": "string", "description": "Assignee user"},
        },
        "required": ["case_id", "title"],
    },
    tags=["thehive", "tasks"],
)
async def thehive_add_task(
    case_id: str,
    title: str,
    description: Optional[str] = None,
    status: str = "waiting",
    assignee: Optional[str] = None,
) -> Dict[str, Any]:
    payload = {"title": title, "description": description or "", "status": status}
    if assignee:
        payload["assignee"] = assignee
    return await _thehive_request("POST", f"/case/{case_id}/task", json=payload)


@mcp_tool(
    name="thehive_add_comment",
    description="Add a comment to a case",
    input_schema={
        "type": "object",
        "properties": {
            "case_id": {"type": "string", "description": "Case ID"},
            "message": {"type": "string", "description": "Comment message"},
        },
        "required": ["case_id", "message"],
    },
    tags=["thehive", "comments"],
)
async def thehive_add_comment(case_id: str, message: str) -> Dict[str, Any]:
    return await _thehive_request("POST", f"/case/{case_id}/comment", json={"message": message})


@mcp_tool(
    name="thehive_close_case",
    description="Close/resolve a case",
    input_schema={
        "type": "object",
        "properties": {
            "case_id": {"type": "string", "description": "Case ID"},
            "resolution_status": {"type": "string", "description": "Resolution status"},
            "summary": {"type": "string", "description": "Resolution summary"},
        },
        "required": ["case_id"],
    },
    tags=["thehive", "cases", "response"],
    requires_approval=True,
)
async def thehive_close_case(
    case_id: str,
    resolution_status: Optional[str] = None,
    summary: Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"status": "Resolved"}
    if resolution_status:
        payload["resolutionStatus"] = resolution_status
    if summary:
        payload["summary"] = summary
    await _thehive_request("PATCH", f"/case/{case_id}", json=payload)
    return {"success": True, "message": f"Case {case_id} closed"}
