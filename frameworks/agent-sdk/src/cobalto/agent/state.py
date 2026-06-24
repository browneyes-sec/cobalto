"""
Agent state definitions for LangGraph workflows.
Defines the typed state that flows through agent pipelines.
"""

from typing import Optional, List, Dict, Any, Annotated, Literal
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ANALYZED = "analyzed"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    QUARANTINE_FILE = "quarantine_file"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY = "notify"
    ESCALATE = "escalate"


class AgentState(BaseModel):
    """Base state for all agents."""
    alert_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}
    errors: List[str] = []
    warnings: List[str] = []


class AlertState(AgentState):
    """State for alert processing."""
    raw_alert: Dict[str, Any] = {}
    source: str = ""
    event_type: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    severity: Severity = Severity.INFORMATIONAL
    status: AlertStatus = AlertStatus.NEW
    tags: List[str] = []
    raw_log: str = ""


class InvestigationState(AgentState):
    """State for investigation workflows."""
    alert_state: Optional[AlertState] = None
    triage_result: Optional[Dict[str, Any]] = None
    enrichment_results: List[Dict[str, Any]] = []
    mitre_techniques: List[Dict[str, Any]] = []
    threat_intel_results: List[Dict[str, Any]] = []
    attack_path: List[str] = []
    risk_score: float = 0.0
    risk_factors: List[str] = []
    recommended_actions: List[Dict[str, Any]] = []
    approved_actions: List[Dict[str, Any]] = []
    executed_actions: List[Dict[str, Any]] = []
    investigation_summary: str = ""
    iocs_found: List[Dict[str, Any]] = []
    related_cases: List[str] = []
    evidence: List[Dict[str, Any]] = []


class ResponseState(AgentState):
    """State for response actions."""
    investigation_state: Optional[InvestigationState] = None
    action_plan: List[Dict[str, Any]] = []
    approval_required: List[str] = []
    approval_status: Dict[str, str] = {}
    execution_results: List[Dict[str, Any]] = []
    rollback_plan: List[Dict[str, Any]] = []
    containment_actions: List[Dict[str, Any]] = []
    remediation_actions: List[Dict[str, Any]] = []
    notification_sent: bool = False


class ThreatHuntState(AgentState):
    """State for threat hunting."""
    hypothesis: str = ""
    search_queries: List[str] = []
    data_sources: List[str] = []
    findings: List[Dict[str, Any]] = []
    indicators: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []
    recommendations: List[str] = []


class DocumentationState(AgentState):
    """State for documentation generation."""
    investigation_state: Optional[InvestigationState] = None
    response_state: Optional[ResponseState] = None
    report_sections: List[Dict[str, Any]] = []
    executive_summary: str = ""
    technical_details: str = ""
    recommendations: List[str] = []
    mitre_mapping: Dict[str, Any] = {}
    timeline: List[Dict[str, Any]] = []
    evidence_summary: str = ""
    lessons_learned: List[str] = []


def merge_states(*states: AgentState) -> AgentState:
    """Merge multiple states into one."""
    merged = AgentState(alert_id=states[0].alert_id)
    for state in states:
        merged.metadata.update(state.metadata)
        merged.errors.extend(state.errors)
        merged.warnings.extend(state.warnings)
    return merged