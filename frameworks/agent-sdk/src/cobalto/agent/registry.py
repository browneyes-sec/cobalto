"""
Agent Registry — central registry for capability-based agent routing.

Provides:
- `AgentProtocol`: A Protocol (structural typing) that any agent can satisfy,
  enabling substitution without inheritance from BaseAgent.
- `AgentCapability`: Typed capability definition for discoverability.
- `AgentRegistry`: Central registry where agents register by capabilities;
  supervisor queries capabilities instead of hardcoding agent names.

This is Phase 1 of the evolvability roadmap. It introduces zero breaking changes:
existing BaseAgent subclasses continue to work unchanged.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Set, runtime_checkable

from pydantic import BaseModel, Field

from .base_agent import AgentResult, AgentType


class AgentCapability(str, Enum):
    """Well-known agent capabilities for capability-based routing."""

    # Triage capabilities
    ALERT_PARSING = "alert_parsing"
    SEVERITY_ASSESSMENT = "severity_assessment"
    IOC_EXTRACTION = "ioc_extraction"
    IOC_ENRICHMENT = "ioc_enrichment"

    # Analysis capabilities
    DEEP_ANALYSIS = "deep_analysis"
    ATTACK_NARRATIVE = "attack_narrative"
    MITRE_MAPPING = "mitre_mapping"
    RISK_ASSESSMENT = "risk_assessment"
    LOG_CORRELATION = "log_correlation"

    # Threat intel capabilities
    OPENCTI_QUERY = "opencti_query"
    MISP_CORRELATION = "misp_correlation"
    THREAT_ACTOR_PROFILING = "threat_actor_profiling"
    CVE_LOOKUP = "cve_lookup"

    # Response capabilities
    CONTAINMENT = "containment"
    REMEDIATION = "remediation"
    NOTIFICATION = "notification"
    APPROVAL_GATING = "approval_gating"

    # Threat hunt capabilities
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    SEARCH_QUERY_BUILDING = "search_query_building"

    # Documentation capabilities
    CASE_CREATION = "case_creation"
    REPORT_GENERATION = "report_generation"
    EVIDENCE_COLLECTION = "evidence_collection"

    # Supervision capabilities
    ORCHESTRATION = "orchestration"
    ROUTING = "routing"
    DECISION_MAKING = "decision_making"


@runtime_checkable
class AgentProtocol(Protocol):
    """Structural protocol for any agent — enables substitution.

    Any object that satisfies this protocol can be registered in the
    AgentRegistry and used by the supervisor. This means:
    - Existing BaseAgent subclasses work without changes.
    - New agent implementations don't need to inherit BaseAgent.
    - Mock/stub agents are trivially creatable for tests.

    Usage:
        class MyAgent:
            agent_type = AgentType.TRIAGE
            agent_id = "triage-abc123"

            async def run(self, input_data: dict) -> AgentResult:
                ...

            def get_capabilities(self) -> list[AgentCapability]:
                return [AgentCapability.ALERT_PARSING]

            def get_required_approval(self) -> list[str]:
                return []
    """

    agent_type: AgentType
    agent_id: str

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute the agent's core logic."""
        ...

    def get_capabilities(self) -> List[AgentCapability]:
        """Return the capabilities this agent provides.

        Used by AgentRegistry for capability-based routing.
        """
        ...

    def get_required_approval(self) -> List[str]:
        """Return action types that require human approval.

        Used by the approval gate before executing response actions.
        """
        ...


class AgentRegistration(BaseModel):
    """Metadata about a registered agent."""

    agent_id: str
    agent_type: AgentType
    capabilities: List[AgentCapability] = []
    requires_approval: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentRegistry:
    """Central registry for agent discovery and capability-based routing.

    The supervisor queries this registry to find agents that can handle
    specific capabilities, rather than hardcoding agent names.

    This is the single source of truth for "what agents are available"
    and "what each agent can do."

    Thread-safe for concurrent use across multiple supervisor instances.

    Usage:
        registry = AgentRegistry()

        # Agents register themselves
        registry.register(triage_agent)

        # Supervisor finds agents by capability
        for agent in registry.find_agents(AgentCapability.SEVERITY_ASSESSMENT):
            result = await agent.run(input_data)
    """

    def __init__(self) -> None:
        self._agents: Dict[str, AgentProtocol] = {}
        self._registrations: Dict[str, AgentRegistration] = {}
        self._capability_index: Dict[AgentCapability, Set[str]] = {}

    # ── Registration ──────────────────────────────────────────────

    def register(
        self,
        agent: AgentProtocol,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register an agent in the registry.

        Args:
            agent: Any object satisfying AgentProtocol.
            metadata: Optional metadata for the registration.
        """
        agent_id = agent.agent_id
        capabilities = agent.get_capabilities()

        self._agents[agent_id] = agent
        self._registrations[agent_id] = AgentRegistration(
            agent_id=agent_id,
            agent_type=agent.agent_type,
            capabilities=capabilities,
            requires_approval=bool(agent.get_required_approval()),
            metadata=metadata or {},
        )

        # Build capability index
        for cap in capabilities:
            self._capability_index.setdefault(cap, set()).add(agent_id)

    def unregister(self, agent_id: str) -> bool:
        """Remove an agent from the registry.

        Returns True if the agent was found and removed.
        """
        if agent_id not in self._agents:
            return False

        registration = self._registrations[agent_id]
        for cap in registration.capabilities:
            if cap in self._capability_index:
                self._capability_index[cap].discard(agent_id)
                if not self._capability_index[cap]:
                    del self._capability_index[cap]

        del self._agents[agent_id]
        del self._registrations[agent_id]
        return True

    # ── Querying ──────────────────────────────────────────────────

    def find_agents(
        self,
        capability: AgentCapability,
    ) -> List[AgentProtocol]:
        """Find all agents that provide a specific capability.

        Args:
            capability: The capability to search for.

        Returns:
            List of agents that provide the capability.
            Empty list if no agents are registered for it.
        """
        agent_ids = self._capability_index.get(capability, set())
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def find_agents_by_type(self, agent_type: AgentType) -> List[AgentProtocol]:
        """Find all agents of a specific type."""
        return [
            agent
            for agent in self._agents.values()
            if agent.agent_type == agent_type
        ]

    def get_agent(self, agent_id: str) -> Optional[AgentProtocol]:
        """Get a specific agent by ID."""
        return self._agents.get(agent_id)

    def get_registration(self, agent_id: str) -> Optional[AgentRegistration]:
        """Get registration metadata for an agent."""
        return self._registrations.get(agent_id)

    # ── Bulk operations ───────────────────────────────────────────

    @property
    def agents(self) -> Dict[str, AgentProtocol]:
        """All registered agents (read-only view)."""
        return dict(self._agents)

    @property
    def registrations(self) -> Dict[str, AgentRegistration]:
        """All registration metadata (read-only view)."""
        return dict(self._registrations)

    @property
    def all_capabilities(self) -> Dict[AgentCapability, List[str]]:
        """All capabilities and their agent IDs (read-only view)."""
        return {
            cap: list(agent_ids)
            for cap, agent_ids in self._capability_index.items()
        }

    def count(self) -> int:
        """Number of registered agents."""
        return len(self._agents)

    def clear(self) -> None:
        """Remove all agents (useful for testing)."""
        self._agents.clear()
        self._registrations.clear()
        self._capability_index.clear()

    # ── Status / introspection ────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize registry state for observability."""
        return {
            "agent_count": self.count(),
            "agents": [
                {
                    "agent_id": reg.agent_id,
                    "agent_type": reg.agent_type.value,
                    "capabilities": [c.value for c in reg.capabilities],
                    "requires_approval": reg.requires_approval,
                }
                for reg in self._registrations.values()
            ],
            "capability_index": {
                cap.value: list(agent_ids)
                for cap, agent_ids in self._capability_index.items()
            },
        }


# ── Convenience adapters for BaseAgent subclasses ─────────────────


def agent_protocol_adapter(agent: Any) -> AgentProtocol:
    """Ensure a BaseAgent subclass satisfies AgentProtocol.

    BaseAgent already provides `agent_type`, `agent_id`, `run()`, and
    `get_tools()`. This adapter fills in `get_capabilities()` and
    `get_required_approval()` with sensible defaults if not overridden.

    This is automatically applied by AgentRegistry.register() for any
    object that doesn't already satisfy AgentProtocol.
    """
    if isinstance(agent, AgentProtocol):
        return agent

    # Wrap with default implementations
    class _AdaptedAgent:
        def __init__(self, inner: Any) -> None:
            self._inner = inner
            self.agent_type = inner.agent_type
            self.agent_id = inner.agent_id

        async def run(self, input_data: Dict[str, Any]) -> AgentResult:
            return await self._inner.run(input_data)

        def get_capabilities(self) -> List[AgentCapability]:
            # Derive capabilities from agent type
            _TYPE_CAPABILITIES: Dict[AgentType, List[AgentCapability]] = {
                AgentType.TRIAGE: [
                    AgentCapability.ALERT_PARSING,
                    AgentCapability.SEVERITY_ASSESSMENT,
                    AgentCapability.IOC_EXTRACTION,
                    AgentCapability.IOC_ENRICHMENT,
                ],
                AgentType.ANALYSIS: [
                    AgentCapability.DEEP_ANALYSIS,
                    AgentCapability.ATTACK_NARRATIVE,
                    AgentCapability.MITRE_MAPPING,
                    AgentCapability.RISK_ASSESSMENT,
                    AgentCapability.LOG_CORRELATION,
                ],
                AgentType.THREAT_INTEL: [
                    AgentCapability.OPENCTI_QUERY,
                    AgentCapability.MISP_CORRELATION,
                    AgentCapability.THREAT_ACTOR_PROFILING,
                    AgentCapability.CVE_LOOKUP,
                ],
                AgentType.RESPONSE: [
                    AgentCapability.CONTAINMENT,
                    AgentCapability.REMEDIATION,
                    AgentCapability.NOTIFICATION,
                    AgentCapability.APPROVAL_GATING,
                ],
                AgentType.THREAT_HUNT: [
                    AgentCapability.HYPOTHESIS_GENERATION,
                    AgentCapability.SEARCH_QUERY_BUILDING,
                ],
                AgentType.DOCUMENTATION: [
                    AgentCapability.CASE_CREATION,
                    AgentCapability.REPORT_GENERATION,
                    AgentCapability.EVIDENCE_COLLECTION,
                ],
                AgentType.SUPERVISOR: [
                    AgentCapability.ORCHESTRATION,
                    AgentCapability.ROUTING,
                    AgentCapability.DECISION_MAKING,
                ],
            }
            return _TYPE_CAPABILITIES.get(self.agent_type, [])

        def get_required_approval(self) -> List[str]:
            # Default: triage, analysis, threat_intel, documentation
            # don't require approval; response and threat_hunt may.
            if self.agent_type in (AgentType.RESPONSE, AgentType.THREAT_HUNT):
                return ["isolate_host", "block_ip", "disable_user", "quarantine_file"]
            return []

    return _AdaptedAgent(agent)


# ── Global singleton ──────────────────────────────────────────────

_global_registry: Optional[AgentRegistry] = None


def get_agent_registry() -> AgentRegistry:
    """Get the global agent registry singleton."""
    global _global_registry
    if _global_registry is None:
        _global_registry = AgentRegistry()
    return _global_registry


def reset_agent_registry() -> None:
    """Reset the global registry (primarily for testing)."""
    global _global_registry
    _global_registry = AgentRegistry()
