"""Report generation for MDR operations."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import json


@dataclass
class AlertMetrics:
    total_alerts: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    false_positives: int = 0
    true_positives: int = 0


@dataclass
class CaseMetrics:
    total_cases: int = 0
    open_cases: int = 0
    closed_cases: int = 0
    avg_mttr_minutes: float = 0.0
    sla_breaches: int = 0
    escalation_count: int = 0


@dataclass
class AgentMetrics:
    total_investigations: int = 0
    avg_latency_ms: float = 0.0
    avg_tokens_used: int = 0
    accuracy: float = 0.0
    false_positive_rate: float = 0.0


@dataclass
class CustomerMetrics:
    customer_id: str
    customer_name: str
    alert_count: int = 0
    case_count: int = 0
    mttr_minutes: float = 0.0
    sla_compliance: float = 0.0


class WeeklySummary:
    def __init__(
        self,
        alerts: AlertMetrics,
        cases: CaseMetrics,
        agents: AgentMetrics,
        period_start: datetime,
        period_end: Optional[datetime] = None,
    ):
        self.alerts = alerts
        self.cases = cases
        self.agents = agents
        self.period_start = period_start
        self.period_end = period_end or datetime.utcnow()

    @property
    def total_alerts(self) -> int:
        return self.alerts.total_alerts

    @property
    def fp_rate(self) -> float:
        if self.alerts.total_alerts == 0:
            return 0.0
        return self.alerts.false_positives / self.alerts.total_alerts

    @property
    def true_positive_rate(self) -> float:
        if self.alerts.total_alerts == 0:
            return 0.0
        return self.alerts.true_positives / self.alerts.total_alerts

    @property
    def mttr(self) -> float:
        return self.cases.avg_mttr_minutes

    @property
    def sla_compliance_rate(self) -> float:
        if self.cases.total_cases == 0:
            return 1.0
        return (self.cases.total_cases - self.cases.sla_breaches) / self.cases.total_cases

    def to_markdown(self) -> str:
        lines = [
            f"# Cobalt SOC Weekly Report",
            f"**Period:** {self.period_start.strftime('%Y-%m-%d')} to {self.period_end.strftime('%Y-%m-%d')}",
            "",
            "## Alert Summary",
            f"- **Total Alerts:** {self.total_alerts}",
            f"- Critical: {self.alerts.critical}",
            f"- High: {self.alerts.high}",
            f"- Medium: {self.alerts.medium}",
            f"- Low: {self.alerts.low}",
            f"- **False Positive Rate:** {self.fp_rate:.1%}",
            f"- **True Positive Rate:** {self.true_positive_rate:.1%}",
            "",
            "## Case Metrics",
            f"- **Total Cases:** {self.cases.total_cases}",
            f"- Open: {self.cases.open_cases}",
            f"- Closed: {self.cases.closed_cases}",
            f"- **MTTR:** {self.mttr:.0f} minutes",
            f"- **SLA Breaches:** {self.cases.sla_breaches}",
            f"- **SLA Compliance:** {self.sla_compliance_rate:.1%}",
            f"- Escalations: {self.cases.escalation_count}",
            "",
            "## Agent Performance",
            f"- **Investigations:** {self.agents.total_investigations}",
            f"- **Avg Latency:** {self.agents.avg_latency_ms:.0f}ms",
            f"- **Avg Tokens/Investigation:** {self.agents.avg_tokens_used}",
            f"- **Accuracy:** {self.agents.accuracy:.1%}",
            f"- **FP Rate:** {self.agents.false_positive_rate:.1%}",
        ]
        return "\n".join(lines)

    def to_html(self) -> str:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #fff; }}
        h1 {{ color: #0047AB; }}
        h2 {{ color: #94a3b8; border-bottom: 1px solid #374151; padding-bottom: 8px; }}
        .metric {{ display: flex; justify-content: space-between; padding: 8px 0; }}
        .metric-label {{ color: #9ca3af; }}
        .metric-value {{ font-weight: 600; }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .medium {{ color: #eab308; }}
        .low {{ color: #3b82f6; }}
        .good {{ color: #22c55e; }}
    </style>
</head>
<body>
    <h1>Cobalt SOC Weekly Report</h1>
    <p><strong>Period:</strong> {self.period_start.strftime('%Y-%m-%d')} to {self.period_end.strftime('%Y-%m-%d')}</p>
    <h2>Alert Summary</h2>
    <div class="metric"><span class="metric-label">Total Alerts</span><span class="metric-value">{self.total_alerts}</span></div>
    <div class="metric"><span class="metric-label">Critical</span><span class="metric-value critical">{self.alerts.critical}</span></div>
    <div class="metric"><span class="metric-label">High</span><span class="metric-value high">{self.alerts.high}</span></div>
    <div class="metric"><span class="metric-label">Medium</span><span class="metric-value medium">{self.alerts.medium}</span></div>
    <div class="metric"><span class="metric-label">Low</span><span class="metric-value low">{self.alerts.low}</span></div>
    <div class="metric"><span class="metric-label">False Positive Rate</span><span class="metric-value">{self.fp_rate:.1%}</span></div>
    <h2>Case Metrics</h2>
    <div class="metric"><span class="metric-label">Total Cases</span><span class="metric-value">{self.cases.total_cases}</span></div>
    <div class="metric"><span class="metric-label">MTTR</span><span class="metric-value">{self.mttr:.0f} min</span></div>
    <div class="metric"><span class="metric-label">SLA Compliance</span><span class="metric-value good">{self.sla_compliance_rate:.1%}</span></div>
    <h2>Agent Performance</h2>
    <div class="metric"><span class="metric-label">Accuracy</span><span class="metric-value good">{self.agents.accuracy:.1%}</span></div>
    <div class="metric"><span class="metric-label">Avg Latency</span><span class="metric-value">{self.agents.avg_latency_ms:.0f}ms</span></div>
</body>
</html>
"""

    def to_dict(self) -> dict:
        return {
            "period": {
                "start": self.period_start.isoformat(),
                "end": self.period_end.isoformat(),
            },
            "alerts": {
                "total": self.alerts.total_alerts,
                "critical": self.alerts.critical,
                "high": self.alerts.high,
                "medium": self.alerts.medium,
                "low": self.alerts.low,
                "false_positives": self.alerts.false_positives,
                "fp_rate": self.fp_rate,
            },
            "cases": {
                "total": self.cases.total_cases,
                "open": self.cases.open_cases,
                "closed": self.cases.closed_cases,
                "mttr_minutes": self.cases.avg_mttr_minutes,
                "sla_breaches": self.cases.sla_breaches,
                "sla_compliance": self.sla_compliance_rate,
            },
            "agents": {
                "investigations": self.agents.total_investigations,
                "avg_latency_ms": self.agents.avg_latency_ms,
                "accuracy": self.agents.accuracy,
            },
        }


@dataclass
class CustomerReport:
    customer_id: str
    customer_name: str
    period_start: datetime
    period_end: datetime
    metrics: list[CustomerMetrics] = field(default_factory=list)
    alerts: AlertMetrics = field(default_factory=AlertMetrics)
    cases: CaseMetrics = field(default_factory=CaseMetrics)

    @property
    def total_alerts(self) -> int:
        return self.alerts.total_alerts

    @property
    def sla_compliance(self) -> float:
        if self.cases.total_cases == 0:
            return 1.0
        return (self.cases.total_cases - self.cases.sla_breaches) / self.cases.total_cases

    @property
    def mttr(self) -> float:
        return self.cases.avg_mttr_minutes

    def to_markdown(self) -> str:
        lines = [
            f"# Customer Report: {self.customer_name}",
            f"**Customer ID:** {self.customer_id}",
            f"**Period:** {self.period_start.strftime('%Y-%m-%d')} to {self.period_end.strftime('%Y-%m-%d')}",
            "",
            "## Summary",
            f"- **Total Alerts:** {self.total_alerts}",
            f"- **Total Cases:** {self.cases.total_cases}",
            f"- **MTTR:** {self.mttr:.0f} minutes",
            f"- **SLA Compliance:** {self.sla_compliance:.1%}",
            f"- **SLA Breaches:** {self.cases.sla_breaches}",
            "",
            "## Alert Breakdown",
            f"- Critical: {self.alerts.critical}",
            f"- High: {self.alerts.high}",
            f"- Medium: {self.alerts.medium}",
            f"- Low: {self.alerts.low}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "customer_id": self.customer_id,
            "customer_name": self.customer_name,
            "period": {
                "start": self.period_start.isoformat(),
                "end": self.period_end.isoformat(),
            },
            "alerts": {
                "total": self.alerts.total_alerts,
                "critical": self.alerts.critical,
                "high": self.alerts.high,
                "medium": self.alerts.medium,
                "low": self.alerts.low,
            },
            "cases": {
                "total": self.cases.total_cases,
                "mttr_minutes": self.cases.avg_mttr_minutes,
                "sla_compliance": self.sla_compliance,
                "sla_breaches": self.cases.sla_breaches,
            },
        }
