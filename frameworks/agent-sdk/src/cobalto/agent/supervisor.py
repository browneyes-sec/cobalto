"""
Supervisor agent for orchestrating other agents.
Routes tasks to appropriate agents based on context.

Supports two routing modes:
1. Capability-based routing (new) — queries AgentRegistry for agents
   that provide specific capabilities.
2. Hardcoded routing (legacy) — uses _determine_routing() with
   agent names. Kept for backward compatibility.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from .state import AgentState, Severity
from ..core.logging import get_logger
from ..core.metrics import record_agent_execution

if TYPE_CHECKING:
    from .registry import AgentCapability, AgentRegistry, AgentProtocol

logger = get_logger(__name__)

# Map severity levels to required capabilities
SEVERITY_TO_CAPABILITIES: Dict[str, List[str]] = {
    "critical": [
        "severity_assessment",
        "deep_analysis",
        "containment",
        "remediation",
    ],
    "high": [
        "severity_assessment",
        "deep_analysis",
        "containment",
    ],
    "medium": [
        "ioc_enrichment",
        "log_correlation",
    ],
    "low": [
        "alert_parsing",
    ],
    "informational": [
        "alert_parsing",
    ],
}

# Alert type to capability map for fine-grained routing
ALERT_TYPE_CAPABILITIES: Dict[str, List[str]] = {
    "brute-force": ["ioc_enrichment", "log_correlation"],
    "malware": ["deep_analysis", "threat_actor_profiling", "mitre_mapping"],
    "ransomware": ["deep_analysis", "containment", "remediation", "mitre_mapping"],
    "phishing": ["ioc_enrichment", "threat_actor_profiling"],
    "data-exfiltration": ["deep_analysis", "containment", "log_correlation"],
    "lateral-movement": ["deep_analysis", "log_correlation", "mitre_mapping"],
    "recon": ["alert_parsing", "ioc_enrichment"],
    "policy-violation": ["alert_parsing", "notification"],
}

# Map capabilities to agent types (used when AgentRegistry is not available)
CAPABILITY_TO_AGENT: Dict[str, str] = {
    # Triage
    "alert_parsing": "triage",
    "severity_assessment": "triage",
    "ioc_extraction": "triage",
    "ioc_enrichment": "triage",
    # Analysis
    "deep_analysis": "analysis",
    "attack_narrative": "analysis",
    "mitre_mapping": "analysis",
    "risk_assessment": "analysis",
    "log_correlation": "analysis",
    # Threat intel
    "opencti_query": "threat_intel",
    "misp_correlation": "threat_intel",
    "threat_actor_profiling": "threat_intel",
    "cve_lookup": "threat_intel",
    # Response
    "containment": "response",
    "remediation": "response",
    "notification": "response",
    "approval_gating": "response",
    # Documentation
    "case_creation": "documentation",
    "report_generation": "documentation",
    "evidence_collection": "documentation",
}


class RoutingDecision(BaseModel):
    """Decision on how to route an alert."""

    next_agent: str
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    priority: int = 0
    metadata: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for observability."""
        return self.model_dump()


class SupervisorAgent(BaseAgent):
    """Supervisor agent that routes tasks to specialized agents.

    Two routing modes:
    1. **Capability-based** (preferred): If an AgentRegistry is provided
       (or the global registry is populated), routing queries the registry
       to find agents that provide the needed capabilities.

    2. **Name-based** (fallback): Uses hardcoded agent names mapped from
       capabilities. This preserves backward compatibility when no
       registry is configured.
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        agent_registry: Optional[AgentRegistry] = None,
    ):
        super().__init__(
            config or AgentConfig(
                name="Supervisor Agent",
                agent_type=AgentType.SUPERVISOR,
                description="Routes alerts to appropriate agents based on severity and context",
                model="gpt-4o-mini",
                temperature=0.0,
            )
        )

        # Agent registry for capability-based routing
        self._agent_registry: Optional[AgentRegistry] = agent_registry

        # Legacy routing data
        self._routing_rules: Dict[str, Dict[str, Any]] = {}
        self._agent_capabilities: Dict[str, List[str]] = {}

    # ── Registry integration ─────────────────────────────────────

    @property
    def registry(self) -> Optional[AgentRegistry]:
        """Get the attached AgentRegistry (if any)."""
        return self._agent_registry

    def attach_registry(self, registry: AgentRegistry) -> None:
        """Attach an AgentRegistry for capability-based routing.

        Once attached, the supervisor will query the registry for
        agent capabilities instead of using hardcoded agent names.
        """
        self._agent_registry = registry
        logger.info(
            "supervisor_registry_attached",
            agent_count=registry.count(),
        )

    # ── Legacy agent registration (deprecated) ────────────────────

    def register_agent(self, agent_name: str, capabilities: List[str]) -> None:
        """Register an agent's capabilities (legacy).

        Deprecated: Use AgentRegistry.register() instead, then
        attach the registry via attach_registry().

        Args:
            agent_name: Name of the agent (e.g., "triage").
            capabilities: List of capability strings.
        """
        self._agent_capabilities[agent_name] = capabilities
        logger.info("agent_registered", agent=agent_name, capabilities=capabilities)

    def add_routing_rule(
        self,
        condition: str,
        target_agent: str,
        priority: int = 0,
    ) -> None:
        """Add a routing rule (legacy).

        Rules are evaluated after capability-based routing and can
        override the routing decision if priority > 0.

        Args:
            condition: Simple condition string (e.g., "severity == 'critical'").
            target_agent: Agent name to route to on match.
            priority: Priority of the rule (higher = more important).
        """
        self._routing_rules[condition] = {
            "target_agent": target_agent,
            "priority": priority,
        }

    # ── Required BaseAgent methods ────────────────────────────────

    def get_system_prompt(self) -> str:
        """Get the system prompt for the supervisor."""
        agents_info = self._build_agents_info()
        return f"""You are the Supervisor Agent for the Cobalto Agentic SOC Platform.
Your role is to analyze incoming alerts and route them to the appropriate agent(s).

Available agents and their capabilities:
{agents_info}

Routing strategy:
1. Analyze the alert severity, source, and type
2. Determine which capabilities are required
3. Route to agents that provide those capabilities
4. Return a routing decision with confidence score

Consider:
- Critical/High severity alerts need immediate deep analysis
- Alerts with IOCs need enrichment and threat intel correlation
- Alerts matching threat intel patterns need investigation
- Alerts requiring response actions need approval workflow
- Low severity alerts may only need triage
"""

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get tools available to the supervisor."""
        return []

    # ── Capability-based routing (the new way) ────────────────────

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute the supervisor logic with capability-based routing.

        Args:
            input_data: Dictionary with 'alert_id', 'alert', 'context' keys.

        Returns:
            AgentResult with routing decision and analysis.
        """
        import time as _time
        start_time = _time.time()

        try:
            alert = input_data.get("alert", {})
            alert_type = self._detect_alert_type(alert)
            severity = alert.get("severity", "informational").lower()
            has_iocs = bool(alert.get("source_ip") or alert.get("indicators"))

            # Determine required capabilities
            required_caps = self._determine_required_capabilities(
                severity=severity,
                alert_type=alert_type,
                has_iocs=has_iocs,
            )

            # Find agents that can fulfill the capabilities
            routing = self._route_by_capabilities(
                required_caps=required_caps,
                alert=alert,
                alert_type=alert_type,
            )

            result = AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "routing": routing.to_dict(),
                    "alert_id": alert.get("id"),
                    "severity": severity,
                    "alert_type": alert_type,
                    "has_iocs": has_iocs,
                    "required_capabilities": [c for c in required_caps],
                },
                duration_seconds=_time.time() - start_time,
            )

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
                alert_type=alert_type,
            )

            return result

        except Exception as e:
            duration = _time.time() - start_time
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

    # ── Routing logic ─────────────────────────────────────────────

    def _determine_required_capabilities(
        self,
        severity: str,
        alert_type: str,
        has_iocs: bool,
    ) -> List[str]:
        """Determine what capabilities are needed based on alert context.

        Args:
            severity: Alert severity level.
            alert_type: Detected alert type (e.g., "ransomware").
            has_iocs: Whether the alert contains IOCs.

        Returns:
            Ordered list of required capability strings.
        """
        required: List[str] = []

        # Base capabilities from severity
        required.extend(SEVERITY_TO_CAPABILITIES.get(severity, ["alert_parsing"]))

        # Alert-type-specific capabilities
        type_caps = ALERT_TYPE_CAPABILITIES.get(alert_type, [])
        for cap in type_caps:
            if cap not in required:
                required.append(cap)

        # IOC-based enrichment
        if has_iocs:
            ioc_caps = ["ioc_enrichment", "opencti_query"]
            for cap in ioc_caps:
                if cap not in required:
                    required.append(cap)

        return required

    def _route_by_capabilities(
        self,
        required_caps: List[str],
        alert: Dict[str, Any],
        alert_type: str,
    ) -> RoutingDecision:
        """Route based on required capabilities.

        Uses the AgentRegistry if available, otherwise falls back to
        the hardcoded capability-to-agent mapping.

        Args:
            required_caps: Ordered list of required capabilities.
            alert: The alert data.
            alert_type: Detected alert type.

        Returns:
            RoutingDecision with the target agent and reasoning.
        """
        if self._agent_registry is not None and self._agent_registry.count() > 0:
            return self._route_via_registry(required_caps, alert)

        return self._route_via_mapping(required_caps, alert, alert_type)

    def _route_via_registry(
        self,
        required_caps: List[str],
        alert: Dict[str, Any],
    ) -> RoutingDecision:
        """Route using the AgentRegistry — finds agents by capability.

        This is the preferred routing path. It queries the registry
        for agents providing each capability and selects the best match.
        """
        import time as _time
        from .registry import AgentCapability

        found_agents: Dict[str, float] = {}
        reasons: List[str] = []

        for cap_str in required_caps:
            try:
                cap = AgentCapability(cap_str)
            except ValueError:
                continue

            agents = self._agent_registry.find_agents(cap)
            if agents:
                for agent in agents:
                    agent_name = agent.agent_type.value
                    found_agents[agent_name] = found_agents.get(agent_name, 0) + 1.0
                    reasons.append(f"Capability '{cap_str}' → {agent_name}")

        if not found_agents:
            # Fallback to the default (triage)
            return RoutingDecision(
                next_agent="triage",
                reason="No agents found for required capabilities, defaulting to triage",
                confidence=0.5,
                metadata={"required_capabilities": required_caps, "found_agents": {}},
            )

        # Pick the agent with the most capability matches
        best_agent = max(found_agents, key=found_agents.__getitem__)
        match_score = found_agents[best_agent] / max(len(required_caps), 1)
        confidence = min(0.95, 0.5 + match_score * 0.4)

        return RoutingDecision(
            next_agent=best_agent,
            reason=f"Registry routing: {'; '.join(reasons[:3])}",
            confidence=confidence,
            metadata={
                "required_capabilities": required_caps,
                "found_agents": found_agents,
                "match_score": match_score,
            },
        )

    def _route_via_mapping(
        self,
        required_caps: List[str],
        alert: Dict[str, Any],
        alert_type: str,
    ) -> RoutingDecision:
        """Fallback routing using hardcoded capability → agent mapping.

        This preserves the original behavior when no AgentRegistry is
        configured. Maps each capability to a known agent type.
        """
        severity = alert.get("severity", "informational").lower()
        source_ip = alert.get("source_ip")
        has_iocs = bool(source_ip or alert.get("indicators"))

        # Collect all candidate agents that cover at least one required cap
        candidate_agents: Dict[str, int] = {}
        for cap_str in required_caps:
            agent_name = CAPABILITY_TO_AGENT.get(cap_str)
            if agent_name:
                candidate_agents[agent_name] = candidate_agents.get(agent_name, 0) + 1

        if not candidate_agents:
            return RoutingDecision(
                next_agent="triage",
                reason="Default routing to triage agent",
                confidence=0.8,
            )

        # Severity-based tiebreaker: pick the most appropriate agent
        best_agent = max(candidate_agents, key=candidate_agents.__getitem__)

        # Override based on severity context
        if severity in ("critical", "high"):
            if "analysis" in candidate_agents:
                best_agent = "analysis"
            elif "response" in candidate_agents:
                best_agent = "response"

        if has_iocs and best_agent == "triage":
            if "threat_intel" in candidate_agents:
                best_agent = "threat_intel"

        # Build reason string
        matched_caps = [
            cap for cap in required_caps
            if CAPABILITY_TO_AGENT.get(cap) == best_agent
        ]
        reason = f"Capability routing to {best_agent}: {', '.join(matched_caps[:3])}"

        return RoutingDecision(
            next_agent=best_agent,
            reason=reason,
            confidence=0.85,
            metadata={
                "required_capabilities": required_caps,
                "candidate_agents": candidate_agents,
            },
        )

    # ── Legacy routing (kept for backward compatibility) ──────────

    def _determine_routing(self, alert: Dict[str, Any]) -> RoutingDecision:
        """Legacy routing logic — kept for backward compatibility.

        This is the original hardcoded routing used by existing tests.
        New code should use the capability-based routing path via run().
        """
        severity = alert.get("severity", "informational").lower()
        source_ip = alert.get("source_ip")
        has_iocs = bool(source_ip or alert.get("indicators"))

        next_agent = "triage"
        reason = "Default routing to triage agent"
        confidence = 0.8

        if severity in ("critical", "high"):
            next_agent = "analysis"
            reason = "High/critical severity alert requires deep analysis"
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

        if has_iocs and next_agent == "triage":
            next_agent = "threat_intel"
            reason = "Alert contains IOCs, routing to threat intel"
            confidence = 0.85

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
        """Evaluate a routing condition against an alert.

        Simple condition parser. In production, this would use
        a proper rule engine (e.g., OPA/Rego).

        Supported operators: ==, !=, in
        """
        try:
            parts = condition.split()
            if len(parts) == 3:
                field, op, value = parts
                alert_value = alert.get(field)
                if op == "==":
                    return str(alert_value) == value.strip("'\"")
                elif op == "!=":
                    return str(alert_value) != value.strip("'\"")
                elif op == "in":
                    return value.strip("'\"") in str(alert_value)
            return False
        except Exception:
            return False

    # ── Helpers ───────────────────────────────────────────────────

    def _detect_alert_type(self, alert: Dict[str, Any]) -> str:
        """Detect alert type from alert data."""
        rule_desc = alert.get("rule_description", "").lower()
        for pattern, alert_type in [
            ("brute", "brute-force"),
            ("malware", "malware"),
            ("ransomware", "ransomware"),
            ("phishing", "phishing"),
            ("exfiltration", "data-exfiltration"),
            ("lateral", "lateral-movement"),
            ("recon", "recon"),
            ("policy", "policy-violation"),
        ]:
            if pattern in rule_desc:
                return alert_type
        return "unknown"

    def _build_agents_info(self) -> str:
        """Build agent information string for the system prompt."""
        if self._agent_registry and self._agent_registry.count() > 0:
            return "\n".join([
                f"- {reg.agent_type.value}: {', '.join(c.value for c in reg.capabilities)}"
                for reg in self._agent_registry.registrations.values()
            ])

        if self._agent_capabilities:
            return "\n".join([
                f"- {name}: {', '.join(caps)}"
                for name, caps in self._agent_capabilities.items()
            ])

        # Fallback: use the hardcoded capability map
        agent_names = set(CAPABILITY_TO_AGENT.values())
        return "\n".join([
            f"- {name}: provides {', '.join(cap for cap, agent in CAPABILITY_TO_AGENT.items() if agent == name)}"
            for name in sorted(agent_names)
        ])

    def get_stats(self) -> Dict[str, Any]:
        """Get supervisor statistics."""
        stats = super().get_stats()
        stats.update({
            "routing_mode": "registry" if self._agent_registry else "legacy",
            "registered_agents": len(self._agent_capabilities),
            "routing_rules": len(self._routing_rules),
        })
        if self._agent_registry:
            stats["registry_agent_count"] = self._agent_registry.count()
        return stats
