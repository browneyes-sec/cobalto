"""
OpenCTI MCP Tools - Tools for interacting with OpenCTI Threat Intelligence Platform.
All requests use the pooled HTTP client with circuit breaker.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.registry.resources import mcp_resource
from cobalto.mcp.transport.pool import execute_request


async def _opencti_query(query: str, variables: Dict[str, Any]) -> Any:
    from cobalto.core.config import get_settings
    settings = get_settings()
    return await execute_request(
        name="opencti",
        base_url=settings.opencti_url.rstrip("/graphql"),
        method="POST",
        path="/graphql",
        json={"query": query, "variables": variables},
        headers={"Authorization": f"Bearer {settings.opencti_token}"},
    )


@mcp_tool(
    name="opencti_search_indicators",
    description="Search for threat indicators in OpenCTI",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "type": {"type": "string", "description": "Indicator type (IPv4, IPv6, Domain, URL, FileHash-MD5, FileHash-SHA256)"},
            "limit": {"type": "integer", "default": 20},
        },
        "required": ["query"],
    },
    tags=["opencti", "threat-intel", "indicators"],
)
async def opencti_search_indicators(
    query: str,
    type: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    graphql_query = """
    query SearchIndicators($query: String!, $type: String, $limit: Int) {
        indicators(search: $query, indicatorTypes: [$type], first: $limit) {
            edges {
                node {
                    id
                    name
                    type
                    pattern
                    valid_from
                    confidence
                    createBy { name }
                    objectLabel { name }
                }
            }
        }
    }
    """
    return await _opencti_query(graphql_query, {"query": query, "type": type, "limit": limit})


@mcp_tool(
    name="opencti_get_threat_actor",
    description="Get threat actor details from OpenCTI",
    input_schema={
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Threat actor ID"},
            "name": {"type": "string", "description": "Threat actor name (alternative to ID)"},
        },
        "required": [],
    },
    tags=["opencti", "threat-intel", "threat-actors"],
)
async def opencti_get_threat_actor(
    id: Optional[str] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    if id:
        query = """
        query GetThreatActor($id: ID!) {
            threatActor(id: $id) {
                id name description firstSeen lastSeen goals
                sophistication resourceLevel primaryMotivation
                objectLabel { name }
                indicators { edges { node { id name type } } }
            }
        }
        """
        variables = {"id": id}
    elif name:
        query = """
        query SearchThreatActor($name: String!) {
            threatActors(search: $name, first: 1) {
                edges { node { id name description firstSeen lastSeen goals sophistication resourceLevel primaryMotivation } }
            }
        }
        """
        variables = {"name": name}
    else:
        return {"error": "Either id or name must be provided"}
    return await _opencti_query(query, variables)


@mcp_tool(
    name="opencti_get_mitre_attack",
    description="Get MITRE ATT&CK techniques from OpenCTI",
    input_schema={
        "type": "object",
        "properties": {
            "technique_id": {"type": "string", "description": "MITRE technique ID (e.g., T1059)"},
            "limit": {"type": "integer", "default": 20},
        },
        "required": [],
    },
    tags=["opencti", "mitre", "attack"],
)
async def opencti_get_mitre_attack(
    technique_id: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    if technique_id:
        query = """
        query GetAttackPattern($id: String!) {
            attackPatterns(techniqueId: $id, first: 1) {
                edges { node { id name description x_mitre_id x_mitre_platforms x_mitre_detection killChainPhases { phase_name kill_chain_name } } }
            }
        }
        """
        variables = {"id": technique_id}
    else:
        query = """
        query ListAttackPatterns($limit: Int) {
            attackPatterns(first: $limit) {
                edges { node { id name description x_mitre_id x_mitre_platforms } }
            }
        }
        """
        variables = {"limit": limit}
    return await _opencti_query(query, variables)


@mcp_tool(
    name="opencti_enrich_indicator",
    description="Enrich an IOC by looking it up in OpenCTI and related threat intel",
    input_schema={
        "type": "object",
        "properties": {
            "ioc": {"type": "string", "description": "IOC to enrich (IP, domain, hash, URL)"},
            "ioc_type": {"type": "string", "description": "IOC type (auto-detected if not provided)"},
        },
        "required": ["ioc"],
    },
    tags=["opencti", "enrichment", "ioc"],
)
async def opencti_enrich_indicator(
    ioc: str,
    ioc_type: Optional[str] = None,
) -> Dict[str, Any]:
    import re
    if not ioc_type:
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            ioc_type = "IPv4-Addr"
        elif re.match(r'^[a-fA-F0-9]{32}$', ioc):
            ioc_type = "FileHash-MD5"
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
            ioc_type = "FileHash-SHA256"
        elif "://" in ioc:
            ioc_type = "Url"
        elif "." in ioc:
            ioc_type = "Domain-Name"
        else:
            ioc_type = "Stix2-Pattern"

    query = """
    query EnrichIndicator($value: String!, $type: String!) {
        indicators(value: $value, indicatorTypes: [$type], first: 1) {
            edges {
                node { id name type pattern valid_from confidence createBy { name } objectLabel { name } observableValue }
            }
        }
    }
    """
    result = await _opencti_query(query, {"value": ioc, "type": ioc_type})
    result["enrichment"] = {"ioc": ioc, "ioc_type": ioc_type, "source": "opencti"}
    return result


@mcp_resource(
    uri="opencti://indicators/{indicator_id}",
    name="OpenCTI Indicator",
    description="Read an indicator from OpenCTI",
    is_template=True,
    uri_template="opencti://indicators/{indicator_id}",
    tags=["opencti", "indicators"],
)
async def opencti_get_indicator_resource(uri: str) -> Dict[str, Any]:
    indicator_id = uri.split("/")[-1]
    query = """
    query GetIndicator($id: ID!) {
        indicator(id: $id) { id name type pattern valid_from confidence createBy { name } objectLabel { name } }
    }
    """
    return await _opencti_query(query, {"id": indicator_id})
