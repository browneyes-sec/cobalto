from typing import TypedDict, Annotated, Optional
import operator


class AlertPayload(TypedDict):
    alert_id: str
    rule_id: int
    rule_description: str
    alert_level: int
    source_ip: Optional[str]
    dest_ip: Optional[str]
    agent_name: str
    timestamp: str
    raw_log: str


class SOCAgentState(TypedDict):
    alert: AlertPayload
    severity: str
    false_positive_probability: float
    mitre_techniques: list[str]
    attack_narrative: str
    affected_assets: list[str]
    threat_actor_matches: list[dict]
    ioc_enrichment: dict
    response_actions: list[dict]
    human_approved: bool
    approval_timeout: bool
    incident_id: str
    final_report: str
    messages: Annotated[list, operator.add]
