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


@mcp_prompt(
    name="cortex_analyze",
    description="Analyze an observable using Cortex",
    arguments=[
        {"name": "observable", "description": "Observable to analyze (IP, hash, domain)", "required": True},
        {"name": "analyzer_id", "description": "Specific analyzer to use (optional)", "required": False},
    ],
    tags=["cortex", "analysis"],
)
async def cortex_analyze_prompt(observable: str, analyzer_id: Optional[str] = None) -> str:
    """Generate Cortex analysis prompt."""
    analyzer_instruction = f"Use analyzer: {analyzer_id}" if analyzer_id else "Select the most appropriate analyzer for this observable type."

    return f"""You are a malware analyst using Cortex to analyze a suspicious observable.

Observable: {observable}
{analyzer_instruction}

## Analysis Steps:
1. **Select analyzer**: Choose the appropriate analyzer for this observable type
2. **Run analysis**: Execute the analyzer via `cortex_analyze_observable`
3. **Wait for results**: Poll job status until complete
4. **Review report**: Analyze the full report via `cortex_get_job_report`
5. **Document findings**: Record analysis results

## Observable Types:
- IP Address: Use IP analyzers (VirusTotal, AbuseIPDB, Shodan)
- File Hash: Use file analyzers (VirusTotal, YARA, Capa)
- Domain/URL: Use domain analyzers (VirusTotal, URLhaus)

## Output Format:
Provide your analysis as:
- **Observable**: {observable}
- **Analysis Status**: [Malicious | Suspicious | Benign | Unknown]
- **Confidence**: [Low | Medium | High]
- **Indicators Found**: Any additional IOCs discovered
- **MITRE Techniques**: Associated attack techniques
- **Recommended Actions**: Next steps based on analysis"""


@mcp_prompt(
    name="opencti_hunt",
    description="Hunt for threats using OpenCTI",
    arguments=[
        {"name": "campaign", "description": "Threat campaign to hunt for", "required": False},
        {"name": "actor", "description": "Threat actor to hunt for", "required": False},
        {"name": "timeframe_days", "description": "Days to search back", "required": False},
    ],
    tags=["opencti", "hunt"],
)
async def opencti_hunt_prompt(
    campaign: Optional[str] = None,
    actor: Optional[str] = None,
    timeframe_days: int = 30,
) -> str:
    """Generate OpenCTI threat hunting prompt."""
    target = campaign or actor or "recent threat activity"

    return f"""You are a threat intelligence analyst hunting for threats using OpenCTI.

Hunting Target: {target}
Timeframe: Last {timeframe_days} days

## Hunt Steps:
1. **Search indicators**: Look for IOCs related to the target via `opencti_search_indicators`
2. **Enrich findings**: Enrich any found indicators via `opencti_enrich_indicator`
3. **Map to ATT&CK**: Map discovered TTPs via `opencti_get_mitre_attack`
4. **Check threat actors**: Identify associated threat actors via `opencti_get_threat_actor`
5. **Document intelligence**: Create threat intelligence report

## Available Data:
- Indicators: IPs, domains, hashes, URLs
- Threat Actors: APT groups, cybercriminals
- Campaigns: Coordinated attack operations
- Attack Patterns: MITRE ATT&CK techniques

## Output Format:
Provide your hunt findings as:
- **Target**: {target}
- **Indicators Found**: List of IOCs discovered
- **Threat Actors**: Associated threat actors
- **TTPs**: MITRE ATT&CK techniques identified
- **Risk Assessment**: Potential impact and likelihood
- **Recommendations**: Detection and prevention measures"""


@mcp_prompt(
    name="response_plan",
    description="Generate a response plan for an incident",
    arguments=[
        {"name": "incident_summary", "description": "Summary of the incident", "required": True},
        {"name": "severity", "description": "Incident severity", "required": True},
        {"name": "affected_systems", "description": "Systems affected", "required": False},
    ],
    tags=["response", "planning"],
)
async def response_plan_prompt(
    incident_summary: str,
    severity: str,
    affected_systems: Optional[str] = None,
) -> str:
    """Generate response plan prompt."""
    return f"""You are a incident response planner creating a containment and remediation plan.

Incident Summary: {incident_summary}
Severity: {severity}
Affected Systems: {affected_systems or "To be determined"}

## Response Planning Steps:
1. **Assess scope**: Determine full impact using `wazuh_get_alerts` and `wazuh_get_agents`
2. **Enrich IOCs**: Look up indicators via `opencti_enrich_indicator`
3. **Containment**: Block malicious IPs via `wazuh_block_ip` or `isolate_host`
4. **Eradication**: Disable compromised accounts via `disable_user_account`
5. **Create case**: Document in TheHive via `thehive_create_case`
6. **Communicate**: Notify stakeholders

## Severity-Based Actions:
- **Critical**: Immediate isolation, executive notification
- **High**: Rapid containment, SOC escalation
- **Medium**: Controlled response, standard workflow
- **Low**: Monitor and document

## Output Format:
Provide your response plan as:
- **Immediate Actions** (0-1 hour): Critical containment steps
- **Short-term Actions** (1-24 hours): Investigation and eradication
- **Long-term Actions** (1-7 days): Recovery and lessons learned
- **Communication Plan**: Who to notify and when
- **Approval Required**: Actions needing management approval"""


@mcp_prompt(
    name="response_approval",
    description="Review and approve a response action",
    arguments=[
        {"name": "action", "description": "Action to approve", "required": True},
        {"name": "risk_assessment", "description": "Risk assessment", "required": True},
    ],
    tags=["response", "approval"],
)
async def response_approval_prompt(action: str, risk_assessment: str) -> str:
    """Generate response approval prompt."""
    return f"""You are a SOC manager reviewing a response action for approval.

Proposed Action: {action}
Risk Assessment: {risk_assessment}

## Approval Criteria:
1. **Business Impact**: Will this action disrupt business operations?
2. **Proportionality**: Is the action proportional to the threat?
3. **Reversibility**: Can the action be undone if needed?
4. **Evidence**: Is there sufficient evidence to justify the action?
5. **Alternative**: Are there less disruptive alternatives?

## Decision Framework:
- **Approve**: Action is justified, proportional, and evidence-based
- **Modify**: Action needs adjustment (scope, duration, etc.)
- **Reject**: Action is not justified or too risky
- **Defer**: Need more information or investigation

## Output Format:
Provide your decision as:
- **Decision**: [Approve | Modify | Reject | Defer]
- **Rationale**: Why this decision was made
- **Conditions**: Any conditions for approval
- **Alternative**: Suggested alternative if modifying/rejecting
- **Escalation**: Whether escalation is needed"""
