"""
MITRE ATT&CK MCP Tools - Tools for querying MITRE ATT&CK knowledge base.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.registry.resources import mcp_resource


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
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(settings.mitre_attack_url)
        response.raise_for_status()
        data = response.json()

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
    description="Search MITRE ATT&CK techniques",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "tactic": {"type": "string", "description": "Filter by tactic (e.g., execution, persistence)"},
            "platform": {"type": "string", "description": "Filter by platform (Windows, Linux, macOS)"},
            "limit": {"type": "integer", "description": "Max results", "default": 20},
        },
        "required": [],
    },
    tags=["mitre", "attack", "search"],
)
async def mitre_search_techniques(
    query: Optional[str] = None,
    tactic: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """Search MITRE ATT&CK techniques."""
    from cobalto.core.config import get_settings
    import httpx

    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.get(settings.mitre_attack_url)
        response.raise_for_status()
        data = response.json()

        results = []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            ext_ref = obj.get("external_references", [{}])[0]
            technique_id = ext_ref.get("external_id", "")
            name = obj.get("name", "")
            description = obj.get("description", "")

            # Apply filters
            if query and query.lower() not in (name + description).lower():
                continue

            if tactic:
                obj_tactics = [
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("chain_name") == "mitre-attack"
                ]
                if tactic.lower() not in [t.lower() for t in obj_tactics]:
                    continue

            if platform and platform.lower() not in [p.lower() for p in obj.get("x_mitre_platforms", [])]:
                continue

            results.append({
                "technique_id": technique_id,
                "name": name,
                "description": description[:200],
                "tactics": [
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("chain_name") == "mitre-attack"
                ],
                "platforms": obj.get("x_mitre_platforms", []),
            })

            if len(results) >= limit:
                break

        return {
            "count": len(results),
            "techniques": results,
        }


@mcp_tool(
    name="mitre_get_tactics",
    description="Get all MITRE ATT&CK tactics",
    input_schema={
        "type": "object",
        "properties": {},
        "required": [],
    },
    tags=["mitre", "attack", "tactics"],
)
async def mitre_get_tactics() -> Dict[str, Any]:
    """Get MITRE ATT&CK tactics."""
    tactics = [
        {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information for targeting"},
        {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources for operations"},
        {"id": "TA0001", "name": "Initial Access", "description": "Gaining initial foothold"},
        {"id": "TA0002", "name": "Execution", "description": "Running malicious code"},
        {"id": "TA0003", "name": "Persistence", "description": "Maintaining foothold"},
        {"id": "TA0004", "name": "Privilege Escalation", "description": "Gaining higher-level permissions"},
        {"id": "TA0005", "name": "Defense Evasion", "description": "Avoiding detection"},
        {"id": "TA0006", "name": "Credential Access", "description": "Stealing credentials"},
        {"id": "TA0007", "name": "Discovery", "description": "Understanding environment"},
        {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through network"},
        {"id": "TA0009", "name": "Collection", "description": "Gathering target data"},
        {"id": "TA0011", "name": "Command and Control", "description": "Communicating with compromised systems"},
        {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data"},
        {"id": "TA0040", "name": "Impact", "description": "Disrupting operations"},
    ]

    return {"tactics": tactics, "count": len(tactics)}


@mcp_tool(
    name="mitre_map_alert",
    description="Map alert indicators to MITRE ATT&CK techniques",
    input_schema={
        "type": "object",
        "properties": {
            "alert_data": {"type": "object", "description": "Alert data with indicators"},
            "process_name": {"type": "string", "description": "Process name if available"},
            "file_hash": {"type": "string", "description": "File hash if available"},
            "command_line": {"type": "string", "description": "Command line if available"},
        },
        "required": ["alert_data"],
    },
    tags=["mitre", "attack", "mapping"],
)
async def mitre_map_alert(
    alert_data: Dict[str, Any],
    process_name: Optional[str] = None,
    file_hash: Optional[str] = None,
    command_line: Optional[str] = None,
) -> Dict[str, Any]:
    """Map alert to MITRE ATT&CK techniques."""
    # Simple mapping based on common patterns
    techniques = []
    tactics = set()

    # Common process mappings
    process_mappings = {
        "powershell.exe": {"technique": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution"},
        "cmd.exe": {"technique": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "execution"},
        "wscript.exe": {"technique": "T1059.005", "name": "Command and Scripting Interpreter: Visual Basic", "tactic": "execution"},
        "cscript.exe": {"technique": "T1059.005", "name": "Command and Scripting Interpreter: Visual Basic", "tactic": "execution"},
        "mshta.exe": {"technique": "T1218.005", "name": "Signed Binary Proxy Execution: Mshta", "tactic": "defense_evasion"},
        "regsvr32.exe": {"technique": "T1218.010", "name": "Signed Binary Proxy Execution: Regsvr32", "tactic": "defense_evasion"},
        "rundll32.exe": {"technique": "T1218.011", "name": "Signed Binary Proxy Execution: Rundll32", "tactic": "defense_evasion"},
        "certutil.exe": {"technique": "T1105", "name": "Ingress Tool Transfer", "tactic": "command_and_control"},
        "bitsadmin.exe": {"technique": "T1105", "name": "Ingress Tool Transfer", "tactic": "command_and_control"},
    }

    # Check process name
    proc = process_name or alert_data.get("process_name", "")
    if proc.lower() in process_mappings:
        mapping = process_mappings[proc.lower()]
        techniques.append({
            "technique_id": mapping["technique"],
            "name": mapping["name"],
            "confidence": 0.7,
        })
        tactics.add(mapping["tactic"])

    # Check command line patterns
    cmd = command_line or alert_data.get("command_line", "")
    if cmd:
        cmd_patterns = [
            ("curl ", "T1105", "Ingress Tool Transfer", "command_and_control"),
            ("wget ", "T1105", "Ingress Tool Transfer", "command_and_control"),
            ("Invoke-WebRequest", "T1105", "Ingress Tool Transfer", "command_and_control"),
            ("New-NetFirewallRule", "T1562.004", "Impair Defenses: Disable or Modify System Firewall", "defense_evasion"),
            ("Add-MpPreference", "T1562.001", "Impair Defenses: Disable or Modify Tools", "defense_evasion"),
            ("Set-MpPreference", "T1562.001", "Impair Defenses: Disable or Modify Tools", "defense_evasion"),
            ("whoami", "T1033", "System Owner/User Discovery", "discovery"),
            ("net user", "T1087.002", "Account Discovery: Domain Account", "discovery"),
            ("net group", "T1069.002", "Domain Groups", "discovery"),
            ("nltest", "T1482", "Domain Trust Discovery", "discovery"),
            ("nslookup", "T1071.004", "Application Layer Protocol: DNS", "command_and_control"),
            ("ipconfig", "T1016", "System Network Configuration Discovery", "discovery"),
            ("netstat", "T1049", "System Network Connections Discovery", "discovery"),
            ("tasklist", "T1057", "Process Discovery", "discovery"),
            ("schtasks", "T1053.005", "Scheduled Task/Job: Scheduled Task", "execution"),
            ("at ", "T1053.001", "Scheduled Task/Job: At (Linux)", "execution"),
        ]

        for pattern, technique_id, name, tactic in cmd_patterns:
            if pattern.lower() in cmd.lower():
                techniques.append({
                    "technique_id": technique_id,
                    "name": name,
                    "confidence": 0.6,
                })
                tactics.add(tactic)

    # Remove duplicates
    unique_techniques = list({t["technique_id"]: t for t in techniques}.values())

    return {
        "mapped_techniques": unique_techniques,
        "tactics": list(tactics),
        "coverage_score": len(unique_techniques) / 14,  # 14 tactics
        "confidence": sum(t["confidence"] for t in unique_techniques) / max(len(unique_techniques), 1),
    }


@mcp_resource(
    uri="mitre://tactics",
    name="MITRE ATT&CK Tactics",
    description="List of all MITRE ATT&CK tactics",
    tags=["mitre", "attack", "tactics"],
)
async def mitre_tactics_resource(uri: str) -> Dict[str, Any]:
    """Get MITRE tactics resource."""
    tactics = [
        {"id": "TA0043", "name": "Reconnaissance"},
        {"id": "TA0042", "name": "Resource Development"},
        {"id": "TA0001", "name": "Initial Access"},
        {"id": "TA0002", "name": "Execution"},
        {"id": "TA0003", "name": "Persistence"},
        {"id": "TA0004", "name": "Privilege Escalation"},
        {"id": "TA0005", "name": "Defense Evasion"},
        {"id": "TA0006", "name": "Credential Access"},
        {"id": "TA0007", "name": "Discovery"},
        {"id": "TA0008", "name": "Lateral Movement"},
        {"id": "TA0009", "name": "Collection"},
        {"id": "TA0011", "name": "Command and Control"},
        {"id": "TA0010", "name": "Exfiltration"},
        {"id": "TA0040", "name": "Impact"},
    ]
    return {"tactics": tactics}
