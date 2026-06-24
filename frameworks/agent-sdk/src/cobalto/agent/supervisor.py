"""
Supervisor agent for orchestrating other agents.
Routes tasks to appropriate agents based on context.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from .state import AgentState, Severity
from ..core.logging import get_logger
from ..core.metrics import record_agent_execution

logger = get_logger(__name__)


class RoutingDecision(BaseModel):
    """Decision on how to route an alert."""
    next_agent: str
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    priority: int = 0
    metadata: Dict[str, Any] = {}


class SupervisorAgent(BaseAgent):
    """Supervisor agent that routes tasks to other agents."""

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Supervisor Agent",
                agent_type=AgentType.SUPERVISOR,
                description="Routes alerts to appropriate agents based on severity and context",
                model="gpt-4o-mini",
                temperature=0.0,
            )
        super().__init__(config)
        self._routing_rules: Dict[str, Dict[str, Any]] = {}
        self._agent_capabilities: Dict[str, List[str]] = {}

    def register_agent(self, agent_name: str, capabilities: List[str]) -> None:
        """Register an agent's capabilities."""
        self._agent_capabilities[agent_name] = capabilities
        logger.info("agent_registered", agent=agent_name, capabilities=capabilities)

    def add_routing_rule(
        self,
        condition: str,
        target_agent: str,
        priority: int = 0,
    ) -> None:
        """Add a routing rule."""
        self._routing_rules[condition] = {
            "target_agent": target_agent,
            "priority": priority,
        }

    def get_system_prompt(self) -> str:
        """Get the system prompt for the supervisor."""
        agents_info = "\n".join([
            f"- {name}: {', '.join(caps)}"
            for name, caps in self._agent_capabilities.items()
        ])

        return f"""You are the Supervisor Agent for the Cobalto Agentic SOC Platform.
Your role is to analyze incoming alerts and route them to the appropriate agent(s).

Available agents and their capabilities:
{agents_info}

Routing rules:
1. Analyze the alert severity, source, and type
2. Determine which agent(s) should handle the alert
3. Return a routing decision with confidence score

Consider:
- Critical/High severity alerts need immediate analysis
- Alerts with IOCs need enrichment
- Alerts matching threat intel need investigation
- Alerts requiring response actions need approval workflow
"""

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get tools available to the supervisor."""
        return []

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute the supervisor logic."""
        start_time = __import__("time").time()

        try:
            # Extract alert information
            alert = input_data.get("alert", {})
            severity = alert.get("severity", "informational").lower()
            source_ip = alert.get("source_ip")
            has_iocs = bool(source_ip or alert.get("indicators"))

            # Determine routing based on rules and capabilities
            routing = self._determine_routing(alert)

            # Build result
            result = AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "routing": routing.model_dump(),
                    "alert_id": alert.get("id"),
                    "severity": severity,
                    "has_iocs": has_iocs,
                },
                duration_seconds=__import__("time").time() - start_time,
            )

            # Record metrics
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "success",
                result.duration_seconds,
            )

            logger.info(
                "supervisor_routing_complete",
                alert_id=alert.get("id"),
                next_agent=routing.next_agent,
                confidence=routing.confidence,
            )

            return result

        except Exception as e:
            duration = __import__("time").time() - start_time
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "error",
                duration,
            )
            logger.exception("supervisor_routing_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    def _determine_routing(self, alert: Dict[str, Any]) -> RoutingDecision:
        """Determine routing based on alert characteristics."""
        severity = alert.get("severity", "informational").lower()
        source_ip = alert.get("source_ip")
        has_iocs = bool(source_ip or alert.get("indicators"))
        rule_id = alert.get("rule_id", "")

        # Default routing
        next_agent = "triage"
        reason = "Default routing to triage agent"
        confidence = 0.8

        # Severity-based routing
        if severity in ("critical", "high"):
            next_agent = "analysis"
            reason = f"High/critical severity alert requires deep analysis"
            confidence = 0.9
        elif severity == "medium":
            if has_iocs:
                next_agent = "threat_intel"
                reason = "Medium severity with IOCs needs threat intel correlation"
                confidence = 0.85
            else:
                next_agent = "triage"
                reason = "Medium severity alert needs triage"
                confidence = 0.8
        elif severity == "low":
            next_agent = "triage"
            reason = "Low severity alert needs triage"
            confidence = 0.7

        # IOC-based routing override
        if has_iocs and next_agent == "triage":
            next_agent = "threat_intel"
            reason = "Alert contains IOCs, routing to threat intel"
            confidence = 0.85

        # Check routing rules
        for condition, rule in self._routing_rules.items():
            if self._evaluate_condition(condition, alert):
                if rule["priority"] > 0:
                    next_agent = rule["target_agent"]
                    reason = f"Matched routing rule: {condition}"
                    confidence = 0.9
                    break

        return RoutingDecision(
            next_agent=next_agent,
            reason=reason,
            confidence=confidence,
            priority=0 if severity in ("critical", "high") else 1,
        )

    def _evaluate_condition(self, condition: str, alert: Dict[str, Any]) -> bool:
        """Evaluate a routing condition against an alert."""
        # Simple condition evaluation
        # In production, this would use a proper rule engine
        try:
            # Example conditions:
            # "severity == 'critical'"
            # "source_ip in known_bad_ips"
            # "rule_id == '5712'"
            parts = condition.split()
            if len(parts) == 3:
                field, op, value = parts
                alert_value = alert.get(field)
                if op == "==":
                    return str(alert_value) == value.strip("'\"")
                elif op == "!=":
                    return str(alert_value) != value.strip("'\"")
                elif op == "in":
                    # Check if value is in a list
                    return value.strip("'\"") in str(alert_value)
            return False
        except Exception:
            return False