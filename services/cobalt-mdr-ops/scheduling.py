"""MDR scheduling for shift management and alert assignment."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
import json


class ShiftType(Enum):
    DAY = "day"
    EVENING = "evening"
    NIGHT = "night"


@dataclass
class Analyst:
    id: str
    name: str
    email: str
    expertise: list[str] = field(default_factory=list)
    max_concurrent_cases: int = 5
    current_cases: int = 0

    @property
    def available(self) -> bool:
        return self.current_cases < self.max_concurrent_cases

    @property
    def load_percentage(self) -> float:
        if self.max_concurrent_cases == 0:
            return 100.0
        return (self.current_cases / self.max_concurrent_cases) * 100


@dataclass
class Shift:
    id: str
    analyst: Analyst
    shift_type: ShiftType
    start_time: datetime
    end_time: datetime
    handover_notes: Optional[str] = None

    @property
    def is_active(self) -> bool:
        now = datetime.utcnow()
        return self.start_time <= now <= self.end_time

    @property
    def hours_remaining(self) -> float:
        now = datetime.utcnow()
        if now > self.end_time:
            return 0.0
        return (self.end_time - now).total_seconds() / 3600


class ShiftSchedule:
    def __init__(self):
        self.shifts: list[Shift] = []
        self.analysts: list[Analyst] = []

    def add_analyst(self, analyst: Analyst) -> None:
        self.analysts.append(analyst)

    def get_current_shift(self) -> Optional[Shift]:
        for shift in self.shifts:
            if shift.is_active:
                return shift
        return None

    def get_next_shift(self) -> Optional[Shift]:
        now = datetime.utcnow()
        upcoming = [s for s in self.shifts if s.start_time > now]
        if upcoming:
            return min(upcoming, key=lambda s: s.start_time)
        return None

    def schedule_shift(
        self,
        analyst: Analyst,
        shift_type: ShiftType,
        start_time: datetime,
    ) -> Shift:
        duration_hours = {
            ShiftType.DAY: 8,
            ShiftType.EVENING: 8,
            ShiftType.NIGHT: 8,
        }

        shift = Shift(
            id=f"shift-{len(self.shifts) + 1}",
            analyst=analyst,
            shift_type=shift_type,
            start_time=start_time,
            end_time=start_time + timedelta(hours=duration_hours[shift_type]),
        )
        self.shifts.append(shift)
        return shift

    def add_handover_notes(self, shift_id: str, notes: str) -> None:
        for shift in self.shifts:
            if shift.id == shift_id:
                shift.handover_notes = notes
                break

    def get_schedule_for_period(self, start: datetime, end: datetime) -> list[Shift]:
        return [
            s for s in self.shifts
            if s.start_time < end and s.end_time > start
        ]

    def to_dict(self) -> dict:
        return {
            "shifts": [
                {
                    "id": s.id,
                    "analyst": {"id": s.analyst.id, "name": s.analyst.name},
                    "shift_type": s.shift_type.value,
                    "start_time": s.start_time.isoformat(),
                    "end_time": s.end_time.isoformat(),
                    "handover_notes": s.handover_notes,
                }
                for s in self.shifts
            ]
        }


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Alert:
    id: str
    title: str
    severity: Severity
    source: str
    created_at: datetime
    mitre_techniques: list[str] = field(default_factory=list)
    assigned_to: Optional[str] = None


@dataclass
class AssignmentRule:
    severity: Severity
    required_expertise: list[str] = field(default_factory=list)
    prefer_specialist: bool = True
    max_queue_size: int = 10


DEFAULT_ASSIGNMENT_RULES: list[AssignmentRule] = [
    AssignmentRule(
        severity=Severity.CRITICAL,
        required_expertise=["incident_response"],
        prefer_specialist=True,
        max_queue_size=3,
    ),
    AssignmentRule(
        severity=Severity.HIGH,
        required_expertise=["threat_hunting", "incident_response"],
        prefer_specialist=True,
        max_queue_size=5,
    ),
    AssignmentRule(
        severity=Severity.MEDIUM,
        required_expertise=[],
        prefer_specialist=False,
        max_queue_size=8,
    ),
    AssignmentRule(
        severity=Severity.LOW,
        required_expertise=[],
        prefer_specialist=False,
        max_queue_size=10,
    ),
]


class AlertAssignment:
    def __init__(
        self,
        schedule: ShiftSchedule,
        rules: Optional[list[AssignmentRule]] = None,
    ):
        self.schedule = schedule
        self.rules = rules or DEFAULT_ASSIGNMENT_RULES

    def _get_rule_for_severity(self, severity: Severity) -> Optional[AssignmentRule]:
        for rule in self.rules:
            if rule.severity == severity:
                return rule
        return None

    def _score_analyst(
        self,
        analyst: Analyst,
        rule: AssignmentRule,
        alert: Alert,
    ) -> float:
        score = 0.0

        if not analyst.available:
            return -1.0

        expertise_match = len(set(rule.required_expertise) & set(analyst.expertise))
        score += expertise_match * 10.0

        if rule.prefer_specialist and alert.mitre_techniques:
            technique_match = len(set(alert.mitre_techniques) & set(analyst.expertise))
            score += technique_match * 5.0

        score -= analyst.load_percentage * 0.1

        return score

    def assign(self, alert: Alert) -> Optional[Analyst]:
        current_shift = self.schedule.get_current_shift()
        if not current_shift:
            return None

        rule = self._get_rule_for_severity(alert.severity)
        if not rule:
            return None

        current_shift.analyst.current_cases += 1
        alert.assigned_to = current_shift.analyst.id
        return current_shift.analyst

    def assign_from_pool(self, alert: Alert) -> Optional[Analyst]:
        rule = self._get_rule_for_severity(alert.severity)
        if not rule:
            return None

        available_analysts = [a for a in self.schedule.analysts if a.available]
        if not available_analysts:
            return None

        scored = [
            (analyst, self._score_analyst(analyst, rule, alert))
            for analyst in available_analysts
        ]
        scored = [(a, s) for a, s in scored if s >= 0]

        if not scored:
            return None

        scored.sort(key=lambda x: x[1], reverse=True)
        best_analyst = scored[0][0]
        best_analyst.current_cases += 1
        alert.assigned_to = best_analyst.id
        return best_analyst

    def reassign(self, alert: Alert, target_analyst: Analyst) -> bool:
        if not target_analyst.available:
            return False

        if alert.assigned_to:
            for analyst in self.schedule.analysts:
                if analyst.id == alert.assigned_to:
                    analyst.current_cases = max(0, analyst.current_cases - 1)
                    break

        target_analyst.current_cases += 1
        alert.assigned_to = target_analyst.id
        return True
