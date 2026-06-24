"""
MCP Resources - Alert and Case resources.
"""

from typing import Any, Dict, Optional
from cobalto.mcp.registry.resources import mcp_resource


@mcp_resource(
    uri="alerts://recent",
    name="Recent Alerts",
    description="Get recent alerts from the SIEM",
    tags=["alerts", "siem"],
)
async def get_recent_alerts(uri: str) -> Dict[str, Any]:
    """Get recent alerts resource."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient(verify=settings.wazuh_verify_ssl) as client:
        response = await client.get(
            f"{settings.wazuh_url}/alerts",
            params={"limit": 20, "sort": "-timestamp"},
            auth=(settings.wazuh_username, settings.wazuh_password),
        )
        response.raise_for_status()
        return response.json()


@mcp_resource(
    uri="alerts://alert/{alert_id}",
    name="Alert Details",
    description="Get details for a specific alert",
    is_template=True,
    uri_template="alerts://alert/{alert_id}",
    tags=["alerts", "siem"],
)
async def get_alert_details(uri: str) -> Dict[str, Any]:
    """Get alert details resource."""
    alert_id = uri.split("/")[-1]

    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient(verify=settings.wazuh_verify_ssl) as client:
        response = await client.get(
            f"{settings.wazuh_url}/alerts/{alert_id}",
            auth=(settings.wazuh_username, settings.wazuh_password),
        )
        response.raise_for_status()
        return response.json()


@mcp_resource(
    uri="cases://recent",
    name="Recent Cases",
    description="Get recent cases from TheHive",
    tags=["cases", "thehive"],
)
async def get_recent_cases(uri: str) -> Dict[str, Any]:
    """Get recent cases resource."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.thehive_url}/case",
            params={"limit": 20, "sort": "-createdAt"},
            headers={"Authorization": f"Bearer {settings.thehive_token}"},
        )
        response.raise_for_status()
        return response.json()


@mcp_resource(
    uri="cases://case/{case_id}",
    name="Case Details",
    description="Get details for a specific case",
    is_template=True,
    uri_template="cases://case/{case_id}",
    tags=["cases", "thehive"],
)
async def get_case_details(uri: str) -> Dict[str, Any]:
    """Get case details resource."""
    case_id = uri.split("/")[-1]

    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.thehive_url}/case/{case_id}",
            headers={"Authorization": f"Bearer {settings.thehive_token}"},
        )
        response.raise_for_status()
        return response.json()


@mcp_resource(
    uri="mitre://techniques",
    name="MITRE ATT&CK Techniques",
    description="List of MITRE ATT&CK techniques",
    tags=["mitre", "attack"],
)
async def get_mitre_techniques(uri: str) -> Dict[str, Any]:
    """Get MITRE techniques resource."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(settings.mitre_attack_url)
        response.raise_for_status()
        data = response.json()

        # Extract techniques
        techniques = []
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                techniques.append({
                    "id": obj.get("external_references", [{}])[0].get("external_id"),
                    "name": obj.get("name"),
                    "description": obj.get("description", "")[:200],
                })

        return {"techniques": techniques[:100]}  # Limit to 100


@mcp_resource(
    uri="mitre://technique/{technique_id}",
    name="MITRE Technique Details",
    description="Get details for a specific MITRE technique",
    is_template=True,
    uri_template="mitre://technique/{technique_id}",
    tags=["mitre", "attack"],
)
async def get_mitre_technique_details(uri: str) -> Dict[str, Any]:
    """Get MITRE technique details resource."""
    technique_id = uri.split("/")[-1]

    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(settings.mitre_attack_url)
        response.raise_for_status()
        data = response.json()

        # Find specific technique
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                ext_ref = obj.get("external_references", [{}])[0]
                if ext_ref.get("external_id") == technique_id:
                    return {
                        "id": technique_id,
                        "name": obj.get("name"),
                        "description": obj.get("description"),
                        "mitigations": obj.get("x_mitre_detection", ""),
                        "platforms": obj.get("x_mitre_platforms", []),
                    }

        return {"error": f"Technique {technique_id} not found"}
