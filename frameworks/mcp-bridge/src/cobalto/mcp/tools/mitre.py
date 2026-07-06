"""
MITRE ATT&CK MCP Tools - Tools for querying MITRE ATT&CK knowledge base.
All requests use the pooled HTTP client with circuit breaker.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.registry.resources import mcp_resource
from cobalto.mcp.transport.pool import execute_request


def _split_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    return base, path


@mcp_tool(
    name="mitre_get_technique",
    description="Get a MITRE ATT&CK technique by ID",
    input_schema={
        "type": "object",
        "properties": {
            "technique_id": {"type": "string", "description": "Technique ID (e.g., T1059)"},
        },
        "required": ["technique_id"],
    },
    tags=["mitre", "attack", "techniques"],
)
async def mitre_get_technique(technique_id: str) -> Dict[str, Any]:
    """Get MITRE ATT&CK technique."""
    from cobalto.core.config import get_settings
    settings = get_settings()
    base, path = _split_url(settings.mitre_attack_url)
    data = await execute_request(name="mitre", base_url=base, method="GET", path=path)

    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext_ref = obj.get("external_references", [{}])[0]
            if ext_ref.get("external_id") == technique_id:
                return {
                    "id": obj.get("id"),
                    "technique_id": technique_id,
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "detection": obj.get("x_mitre_detection"),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "data_sources": obj.get("x_mitre_data_sources", []),
                    "tactics": [
                        phase.get("phase_name")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("chain_name") == "mitre-attack"
                    ],
                    "mitigations": [
                        ref.get("external_id")
                        for ref in obj.get("external_references", [])
                        if ref.get("source_name") == "mitre-attack"
                    ],
                }
    return {"error": f"Technique {technique_id} not found"}


@mcp_tool(
    name="mitre_search_techniques",
    description="Search MITRE ATT&CK techniques by keyword",
    input_schema={
        "type": "object",
        "properties": {
            "keyword": {"type": "string", "description": "Search keyword"},
            "limit": {"type": "integer", "default": 20},
        },
        "required": ["keyword"],
    },
    tags=["mitre", "attack", "search"],
)
async def mitre_search_techniques(keyword: str, limit: int = 20) -> Dict[str, Any]:
    """Search MITRE ATT&CK techniques."""
    from cobalto.core.config import get_settings
    settings = get_settings()
    base, path = _split_url(settings.mitre_attack_url)
    data = await execute_request(name="mitre", base_url=base, method="GET", path=path)

    keyword_lower = keyword.lower()
    results = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            name = (obj.get("name") or "").lower()
            description = (obj.get("description") or "").lower()
            if keyword_lower in name or keyword_lower in description:
                ext_ref = obj.get("external_references", [{}])[0]
                results.append({
                    "technique_id": ext_ref.get("external_id"),
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "tactics": [
                        phase.get("phase_name")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("chain_name") == "mitre-attack"
                    ],
                })
                if len(results) >= limit:
                    break
    return {"techniques": results}


@mcp_tool(
    name="mitre_get_tactics",
    description="Get list of all MITRE ATT&CK tactics",
    input_schema={
        "type": "object",
        "properties": {},
        "required": [],
    },
    tags=["mitre", "attack", "tactics"],
)
async def mitre_get_tactics() -> Dict[str, Any]:
    """Get MITRE ATT&CK tactics."""
    from cobalto.core.config import get_settings
    settings = get_settings()
    base, path = _split_url(settings.mitre_attack_url)
    data = await execute_request(name="mitre", base_url=base, method="GET", path=path)

    tactics = {}
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("chain_name") == "mitre-attack":
                    tactic = phase.get("phase_name")
                    if tactic and tactic not in tactics:
                        tactics[tactic] = {
                            "name": tactic,
                            "techniques": 0,
                        }
                    if tactic:
                        tactics[tactic]["techniques"] += 1
    return {"tactics": sorted(tactics.values(), key=lambda t: t["name"])}


@mcp_tool(
    name="mitre_get_techniques_by_tactic",
    description="Get all MITRE ATT&CK techniques for a specific tactic",
    input_schema={
        "type": "object",
        "properties": {
            "tactic": {"type": "string", "description": "Tactic name (e.g., execution, persistence)"},
        },
        "required": ["tactic"],
    },
    tags=["mitre", "attack", "techniques"],
)
async def mitre_get_techniques_by_tactic(tactic: str) -> Dict[str, Any]:
    """Get techniques for a MITRE tactic."""
    from cobalto.core.config import get_settings
    settings = get_settings()
    base, path = _split_url(settings.mitre_attack_url)
    data = await execute_request(name="mitre", base_url=base, method="GET", path=path)

    tactic_lower = tactic.lower()
    results = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            phases = obj.get("kill_chain_phases", [])
            match = any(
                phase.get("chain_name") == "mitre-attack" and phase.get("phase_name", "").lower() == tactic_lower
                for phase in phases
            )
            if match:
                ext_ref = obj.get("external_references", [{}])[0]
                results.append({
                    "technique_id": ext_ref.get("external_id"),
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                })
    return {"tactic": tactic, "techniques": results}


@mcp_resource(
    uri="mitre://technique/{technique_id}",
    name="MITRE ATT&CK Technique",
    description="Read a MITRE ATT&CK technique",
    tags=["mitre", "resources"],
    uri_template="mitre://technique/{technique_id}",
    is_template=True,
)
async def mitre_technique_resource(uri: str) -> Dict[str, Any]:
    technique_id = uri.split("/")[-1]
    result = await mitre_get_technique(technique_id)
    return {
        "uri": uri,
        "technique_id": technique_id,
        "content": result,
        "mime_type": "application/json",
    }
