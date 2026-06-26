"""SLA tracking, breach detection, and escalation rules."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional


class Priority(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


@dataclass
class SLADefinition:
    priority: Priority
    response_time_minutes: int
    containment_time_minutes: int
    resolution_time_minutes: int

    def __str__(self) -> str:
        return (
            f"{self.priority.value}: "
            f"response={self.response_time_minutes}m, "
            f"containment={self.containment_time_minutes}m, "
            f"resolution={self.resolution_time_minutes}m"
        )


DEFAULT_SLAS: dict[Priority, SLADefinition] = {
    Priority.P1: SLADefinition(
        priority=Priority.P1,
        response_time_minutes=15,
        containment_time_minutes=60,
        resolution_time_minutes=240,
    ),
    Priority.P2: SLADefinition(
        priority=Priority.P2,
        response_time_minutes=60,
        containment_time_minutes=240,
        resolution_time_minutes=1440,
    ),
    Priority.P3: SLADefinition(
        priority=Priority.P3,
        response_time_minutes=240,
        containment_time_minutes=1440,
        resolution_time_minutes=5760,
    ),
    Priority.P4: SLADefinition(
        priority=Priority.P4,
        response_time_minutes=1440,
        containment_time_minutes=5760,
        resolution_time_minutes=14400,
    ),
}


class SLABreachType(Enum):
    RESPONSE = "response"
    CONTAINMENT = "containment"
    RESOLUTION = "resolution"


@dataclass
class SLAStatus:
    alert_id: str
    priority: Priority
    response_time_remaining: int
    containment_time_remaining: int
    resolution_time_remaining: int
    breached: bool = False
    breach_type: Optional[SLABreachType] = None


class SLACalculator:
    def __init__(self, sla_definitions: Optional[dict[Priority, SLADefinition]] = None):
        self.sla_definitions = sla_definitions or DEFAULT_SLAS

    def calculate_time_remaining(self, created_at: datetime, sla: SLADefinition) -> SLAStatus:
        now = datetime.utcnow()
        elapsed = (now - created_at).total_seconds() / 60

        response_remaining = max(0, sla.response_time_minutes - elapsed)
        containment_remaining = max(0, sla.containment_time_minutes - elapsed)
        resolution_remaining = max(0, sla.resolution_time_minutes - elapsed)

        breached = False
        breach_type = None

        if elapsed > sla.resolution_time_minutes:
            breached = True
            breach_type = SLABreachType.RESOLUTION
        elif elapsed > sla.containment_time_minutes:
            breached = True
            breach_type = SLABreachType.CONTAINMENT
        elif elapsed > sla.response_time_minutes:
            breached = True
            breach_type = SLABreachType.RESPONSE

        return SLAStatus(
            alert_id="",
            priority=sla.priority,
            response_time_remaining=response_remaining,
            containment_time_remaining=containment_remaining,
            resolution_time_remaining=resolution_remaining,
            breached=breached,
            breach_type=breach_type,
        )

    def check_breach(self, created_at: datetime, priority: Priority) -> Optional[SLABreachType]:
        sla = self.sla_definitions.get(priority)
        if not sla:
            return None

        status = self.calculate_time_remaining(created_at, sla)
        return status.breach_type


@dataclass
class EscalationRule:
    priority: Priority
    escalation_delay_minutes: int
    escalation_level: int
    notify_roles: list[str] = field(default_factory=list)
    auto_page: bool = False


DEFAULT_ESCALATION_RULES: list[EscalationRule] = [
    EscalationRule(
        priority=Priority.P1,
        escalation_delay_minutes=5,
        escalation_level=1,
        notify_roles=["soc_team_lead"],
        auto_page=True,
    ),
    EscalationRule(
        priority=Priority.P1,
        escalation_delay_minutes=15,
        escalation_level=2,
        notify_roles=["soc_manager", "ciso"],
        auto_page=True,
    ),
    EscalationRule(
        priority=Priority.P2,
        escalation_delay_minutes=30,
        escalation_level=1,
        notify_roles=["soc_team_lead"],
        auto_page=False,
    ),
    EscalationRule(
        priority=Priority.P2,
        escalation_delay_minutes=60,
        escalation_level=2,
        notify_roles=["soc_manager"],
        auto_page=True,
    ),
    EscalationRule(
        priority=Priority.P3,
        escalation_delay_minutes=120,
        escalation_level=1,
        notify_roles=["soc_team_lead"],
        auto_page=False,
    ),
    EscalationRule(
        priority=Priority.P4,
        escalation_delay_minutes=480,
        escalation_level=1,
        notify_roles=["soc_team_lead"],
        auto_page=False,
    ),
]


class EscalationEngine:
    def __init__(self, rules: Optional[list[EscalationRule]] = None):
        self.rules = rules or DEFAULT_ESCALATION_RULES

    def get_applicable_rules(self, priority: Priority, elapsed_minutes: float) -> list[EscalationRule]:
        applicable = []
        for rule in self.rules:
            if rule.priority == priority and elapsed_minutes >= rule.escalation_delay_minutes:
                applicable.append(rule)
        return sorted(applicable, key=lambda r: r.escalation_level)

    def should_escalate(self, priority: Priority, created_at: datetime, current_level: int = 0) -> Optional[EscalationRule]:
        elapsed = (datetime.utcnow() - created_at).total_seconds() / 60
        applicable = self.get_applicable_rules(priority, elapsed)

        for rule in applicable:
            if rule.escalation_level > current_level:
                return rule
        return None
