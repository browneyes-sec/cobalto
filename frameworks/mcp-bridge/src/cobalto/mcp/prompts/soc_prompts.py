"""
MCP Prompts - Triage and Analysis prompt templates.
"""

from typing import Any, Dict, Optional
from cobalto.mcp.registry.prompts import mcp_prompt


@mcp_prompt(
    name="triage_alert",
    description="Triage a security alert",
    arguments=[
        {"name": "alert_id", "description": "Alert ID to triage", "required": True},
        {"name": "alert_data", "description": "Alert data (JSON)", "required": False},
    ],
    tags=["triage", "workflow"],
)
async def triage_alert_prompt(alert_id: str, alert_data: Optional[str] = None) -> str:
    """Generate triage prompt for an alert."""
    return f"""You are a SOC analyst triaging a security alert.

Alert ID: {alert_id}
{"Alert Data: " + alert_data if alert_data else "Please fetch the alert data using the wazuh_get_alerts tool."}

## Triage Steps:
1. **Identify the alert**: What is the alert about?
2. **Check severity**: What is the alert level/priority?
3. **Identify affected assets**: Which hosts/users are affected?
4. **Check for related alerts**: Are there similar or related alerts?
5. **Determine initial verdict**: True positive, false positive, or needs investigation?

## Output Format:
Provide your triage assessment as:
- **Verdict**: [True Positive | False Positive | Needs Investigation]
- **Confidence**: [Low | Medium | High]
- **Summary**: Brief description of the alert
- **Recommended Actions**: Next steps
- **Escalation Required**: [Yes | No] with reason"""


@mcp_prompt(
    name="analyze_threat",
    description="Analyze a threat or suspicious activity",
    arguments=[
        {"name": "indicator", "description": "IOC to analyze (IP, hash, domain)", "required": True},
        {"name": "context", "description": "Additional context", "required": False},
    ],
    tags=["analysis", "threat"],
)
async def analyze_threat_prompt(indicator: str, context: Optional[str] = None) -> str:
    """Generate threat analysis prompt."""
    return f"""You are a threat intelligence analyst investigating a suspicious indicator.

Indicator: {indicator}
{f"Context: {context}" if context else ""}

## Analysis Steps:
1. **Look up the indicator** in threat intelligence sources
2. **Check reputation** across multiple feeds
3. **Identify related indicators** and threat actors
4. **Map to MITRE ATT&CK** techniques if applicable
5. **Assess risk level** and potential impact

## Tools Available:
- Use `opencti_search_indicators` to search OpenCTI
- Use `opencti_enrich_indicator` to enrich the IOC
- Use `opencti_get_mitre_attack` to map to ATT&CK

## Output Format:
Provide your analysis as:
- **Indicator**: {indicator}
- **Type**: [IP | Domain | Hash | URL]
- **Reputation**: [Malicious | Suspicious | Unknown | Clean]
- **Confidence**: [Low | Medium | High]
- **Threat Actor(s)**: Associated threat actors if known
- **MITRE Technique(s)**: Associated ATT&CK techniques
- **Recommended Actions**: Containment and investigation steps"""


@mcp_prompt(
    name="investigate_case",
    description="Investigate a security case",
    arguments=[
        {"name": "case_id", "description": "Case ID to investigate", "required": True},
        {"name": "case_data", "description": "Case data (JSON)", "required": False},
    ],
    tags=["investigation", "case"],
)
async def investigate_case_prompt(case_id: str, case_data: Optional[str] = None) -> str:
    """Generate investigation prompt for a case."""
    return f"""You are a security investigator working on a case.

Case ID: {case_id}
{f"Case Data: {case_data}" if case_data else "Please fetch case details using the thehive_get_case tool."}

## Investigation Steps:
1. **Review case details**: Understand the scope and timeline
2. **Analyze observables**: Investigate all IOCs in the case
3. **Correlate alerts**: Find related alerts and events
4. **Identify root cause**: Determine how the incident occurred
5. **Document findings**: Create comprehensive investigation notes

## Tools Available:
- Use `thehive_get_case` to get case details
- Use `thehive_get_observables` to list IOCs
- Use `opencti_enrich_indicator` to enrich indicators
- Use `wazuh_get_alerts` to find related alerts

## Output Format:
Provide your investigation findings as:
- **Executive Summary**: High-level overview
- **Timeline**: Key events in chronological order
- **Indicators**: All IOCs with reputation
- **Impact Assessment**: What was affected
- **Root Cause**: How the incident occurred
- **Recommendations**: Remediation steps"""


@mcp_prompt(
    name="create_incident_report",
    description="Create an incident report",
    arguments=[
        {"name": "case_id", "description": "Case ID for the report", "required": True},
        {"name": "findings", "description": "Investigation findings", "required": True},
    ],
    tags=["report", "documentation"],
)
async def create_incident_report_prompt(case_id: str, findings: str) -> str:
    """Generate incident report prompt."""
    return f"""You are creating a formal incident report for a security incident.

Case ID: {case_id}
Investigation Findings: {findings}

## Report Sections:
1. **Executive Summary**: Brief overview for leadership
2. **Incident Details**: What happened, when, who was affected
3. **Timeline**: Detailed chronological timeline
4. **Technical Analysis**: Root cause, attack vectors, IOCs
5. **Impact Assessment**: Business impact and data exposure
6. **Response Actions**: What was done to contain/remediate
7. **Recommendations**: Preventive measures
8. **Appendix**: IOCs, screenshots, evidence

## Output Format:
Create a well-structured incident report in Markdown format following the sections above.
Use professional language suitable for both technical and executive audiences."""


@mcp_prompt(
    name="threat_hunt",
    description="Proactive threat hunting",
    arguments=[
        {"name": "hypothesis", "description": "Hunting hypothesis", "required": True},
        {"name": "scope", "description": "Scope of the hunt", "required": False},
    ],
    tags=["hunt", "proactive"],
)
async def threat_hunt_prompt(hypothesis: str, scope: Optional[str] = None) -> str:
    """Generate threat hunting prompt."""
    return f"""You are a threat hunter conducting a proactive investigation.

Hypothesis: {hypothesis}
{f"Scope: {scope}" if scope else "Scope: All available data sources"}

## Hunt Steps:
1. **Validate hypothesis**: Is the hypothesis valid based on available data?
2. **Identify data sources**: What logs and data should be examined?
3. **Develop detection queries**: Create queries to test the hypothesis
4. **Analyze results**: Look for anomalies and suspicious patterns
5. **Document findings**: Record what was found (or not found)

## Tools Available:
- Use `wazuh_get_alerts` to search for alert patterns
- Use `opencti_search_indicators` to hunt for IOCs
- Use `thehive_get_cases` to review related cases

## Output Format:
Provide your hunt results as:
- **Hypothesis**: {hypothesis}
- **Data Sources Reviewed**: List of sources checked
- **Queries Executed**: Detection queries used
- **Findings**: What was discovered
- **Verdict**: [Hypothesis Confirmed | Inconclusive | Hypothesis Rejected]
- **Recommendations**: Next steps or detection improvements"""
