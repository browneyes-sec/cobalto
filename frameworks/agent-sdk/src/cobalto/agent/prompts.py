"""
Prompt management for agents.
Provides templates and versioning for prompts.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import json
import hashlib


class PromptTemplate(BaseModel):
    """A prompt template with variables."""
    name: str
    template: str
    description: str = ""
    variables: List[str] = []
    version: str = "1.0.0"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}

    def render(self, **kwargs: Any) -> str:
        """Render the template with variables."""
        rendered = self.template
        for key, value in kwargs.items():
            placeholder = f"{{{key}}}"
            rendered = rendered.replace(placeholder, str(value))
        return rendered

    def get_hash(self) -> str:
        """Get hash of the template."""
        return hashlib.sha256(self.template.encode()).hexdigest()[:16]


class PromptManager:
    """Manages prompt templates for agents."""

    def __init__(self):
        self._templates: Dict[str, PromptTemplate] = {}
        self._versions: Dict[str, List[PromptTemplate]] = {}

    def register(self, template: PromptTemplate) -> None:
        """Register a prompt template."""
        self._templates[template.name] = template
        if template.name not in self._versions:
            self._versions[template.name] = []
        self._versions[template.name].append(template)

    def get(self, name: str, version: Optional[str] = None) -> Optional[PromptTemplate]:
        """Get a prompt template."""
        if version:
            versions = self._versions.get(name, [])
            for v in versions:
                if v.version == version:
                    return v
            return None
        return self._templates.get(name)

    def render(self, name: str, **kwargs: Any) -> str:
        """Render a prompt template."""
        template = self.get(name)
        if template is None:
            raise ValueError(f"Template '{name}' not found")
        return template.render(**kwargs)

    def list_templates(self) -> List[Dict[str, Any]]:
        """List all registered templates."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "version": t.version,
                "variables": t.variables,
            }
            for t in self._templates.values()
        ]

    def update(self, name: str, new_template: str, version: Optional[str] = None) -> PromptTemplate:
        """Update a prompt template."""
        existing = self.get(name)
        if existing is None:
            raise ValueError(f"Template '{name}' not found")

        new_version = version or self._bump_version(existing.version)
        updated = PromptTemplate(
            name=name,
            template=new_template,
            description=existing.description,
            variables=existing.variables,
            version=new_version,
            metadata=existing.metadata,
        )
        self.register(updated)
        return updated

    def _bump_version(self, version: str) -> str:
        """Bump patch version."""
        parts = version.split(".")
        if len(parts) == 3:
            major, minor, patch = parts
            return f"{major}.{minor}.{int(patch) + 1}"
        return "1.0.1"


# Global prompt manager
_prompt_manager = PromptManager()


def get_prompt_manager() -> PromptManager:
    """Get the global prompt manager."""
    return _prompt_manager


# Pre-defined prompt templates
TRIAGE_SYSTEM_PROMPT = PromptTemplate(
    name="triage_system",
    template="""You are a SOC Triage Agent for the Cobalto Agentic SOC Platform.

Your role is to analyze security alerts and provide initial assessment.

## Alert Information
Alert ID: {alert_id}
Source: {source}
Severity: {severity}
Timestamp: {timestamp}

## Raw Alert Data
{raw_alert}

## Instructions
1. Parse the alert and extract key indicators (IPs, domains, hashes, users)
2. Classify the alert type (network, endpoint, identity, cloud)
3. Assess the severity based on context
4. Recommend initial investigation steps

## Output Format
Provide your triage as a JSON object with:
- alert_type: classification
- severity_assessment: your severity rating
- indicators: list of IOCs found
- investigation_steps: recommended next actions
- confidence: your confidence score (0-1)
""",
    description="System prompt for triage agent",
    variables=["alert_id", "source", "severity", "timestamp", "raw_alert"],
)

ANALYSIS_SYSTEM_PROMPT = PromptTemplate(
    name="analysis_system",
    template="""You are a SOC Analysis Agent for the Cobalto Agentic SOC Platform.

Your role is to perform deep analysis of security alerts and correlate with threat intelligence.

## Investigation Context
Alert ID: {alert_id}
Triage Result: {triage_result}
Enrichment Data: {enrichment_data}

## MITRE ATT&CK Techniques
{mitre_techniques}

## Instructions
1. Analyze the alert in context of the triage result
2. Correlate with MITRE ATT&CK techniques
3. Build an attack narrative
4. Assess risk and impact
5. Recommend response actions

## Output Format
Provide your analysis as a JSON object with:
- attack_narrative: description of the attack
- mitre_techniques: list of matched techniques
- risk_score: 0-100 score
- risk_factors: list of risk factors
- recommended_actions: suggested response actions
- confidence: your confidence score (0-1)
""",
    description="System prompt for analysis agent",
    variables=["alert_id", "triage_result", "enrichment_data", "mitre_techniques"],
)

THREAT_INTEL_SYSTEM_PROMPT = PromptTemplate(
    name="threat_intel_system",
    template="""You are a Threat Intelligence Agent for the Cobalto Agentic SOC Platform.

Your role is to correlate alerts with threat intelligence and identify threat actors.

## Investigation Context
Alert ID: {alert_id}
Indicators: {indicators}
MITRE Techniques: {mitre_techniques}

## Threat Intelligence Data
{threat_intel_data}

## Instructions
1. Correlate indicators with known threat intelligence
2. Identify potential threat actors
3. Assess the threat landscape
4. Provide context on attack campaigns
5. Recommend threat hunting queries

## Output Format
Provide your analysis as a JSON object with:
- threat_actors: identified threat actors
- campaigns: related campaigns
- confidence: your confidence score (0-1)
- threat_level: critical/high/medium/low
- recommendations: suggested actions
""",
    description="System prompt for threat intel agent",
    variables=["alert_id", "indicators", "mitre_techniques", "threat_intel_data"],
)

RESPONSE_SYSTEM_PROMPT = PromptTemplate(
    name="response_system",
    template="""You are a Response Agent for the Cobalto Agentic SOC Platform.

Your role is to generate response actions for security incidents.

## Investigation Context
Alert ID: {alert_id}
Analysis: {analysis}
Risk Score: {risk_score}

## Available Actions
{available_actions}

## Instructions
1. Generate appropriate response actions based on the analysis
2. Classify actions by risk level
3. Determine if approval is required
4. Create a rollback plan
5. Prioritize actions

## Output Format
Provide your response plan as a JSON object with:
- actions: list of actions to execute
- containment_actions: immediate containment
- remediation_actions: long-term fixes
- approval_required: list of actions needing approval
- rollback_plan: steps to undo actions
- priority: action priority
""",
    description="System prompt for response agent",
    variables=["alert_id", "analysis", "risk_score", "available_actions"],
)

DOCUMENTATION_SYSTEM_PROMPT = PromptTemplate(
    name="documentation_system",
    template="""You are a Documentation Agent for the Cobalto Agentic SOC Platform.

Your role is to generate comprehensive incident reports.

## Investigation Context
Alert ID: {alert_id}
Investigation Summary: {investigation_summary}
Response Actions: {response_actions}

## Timeline
{timeline}

## Instructions
1. Generate a comprehensive incident report
2. Include executive summary
3. Document technical details
4. Provide recommendations
5. Include MITRE ATT&CK mapping

## Output Format
Provide your report as a JSON object with:
- executive_summary: high-level summary
- technical_details: detailed analysis
- timeline: investigation timeline
- recommendations: suggested improvements
- mitre_mapping: ATT&CK technique mapping
- lessons_learned: key takeaways
""",
    description="System prompt for documentation agent",
    variables=["alert_id", "investigation_summary", "response_actions", "timeline"],
)


def register_default_prompts() -> None:
    """Register default prompt templates."""
    manager = get_prompt_manager()
    manager.register(TRIAGE_SYSTEM_PROMPT)
    manager.register(ANALYSIS_SYSTEM_PROMPT)
    manager.register(THREAT_INTEL_SYSTEM_PROMPT)
    manager.register(RESPONSE_SYSTEM_PROMPT)
    manager.register(DOCUMENTATION_SYSTEM_PROMPT)