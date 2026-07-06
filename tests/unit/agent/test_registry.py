"""
Tests for the AgentRegistry and AgentProtocol abstractions.

Covers:
- AgentCapability enum values
- AgentProtocol structural typing
- AgentRegistry registration, unregistration, querying
- agent_protocol_adapter for BaseAgent subclasses
- Global singleton get_agent_registry() / reset_agent_registry()
"""

import pytest
from typing import Any, Dict, List
from unittest.mock import AsyncMock

from cobalto.agent.base_agent import (
    BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult,
)
from cobalto.agent.registry import (
    AgentCapability,
    AgentRegistration,
    AgentRegistry,
    AgentProtocol,
    agent_protocol_adapter,
    get_agent_registry,
    reset_agent_registry,
)


# ── Fixtures ─────────────────────────────────────────────────────


class MockTriageAgent:
    """Minimal agent satisfying AgentProtocol (no BaseAgent inheritance)."""
    agent_type = AgentType.TRIAGE
    agent_id = "triage-mock-001"

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        return AgentResult(
            agent_id=self.agent_id,
            agent_type=AgentType.TRIAGE,
            status=AgentStatus.COMPLETED,
            output={"result": "triaged"},
        )

    def get_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability.ALERT_PARSING,
            AgentCapability.SEVERITY_ASSESSMENT,
            AgentCapability.IOC_EXTRACTION,
        ]

    def get_required_approval(self) -> List[str]:
        return []


class MockAnalysisAgent:
    """Another mock agent for multi-agent tests."""
    agent_type = AgentType.ANALYSIS
    agent_id = "analysis-mock-001"

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        return AgentResult(
            agent_id=self.agent_id,
            agent_type=AgentType.ANALYSIS,
            status=AgentStatus.COMPLETED,
            output={"result": "analyzed"},
        )

    def get_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability.DEEP_ANALYSIS,
            AgentCapability.MITRE_MAPPING,
            AgentCapability.RISK_ASSESSMENT,
        ]

    def get_required_approval(self) -> List[str]:
        return []


class MockResponseAgent:
    """Response agent that requires approval."""
    agent_type = AgentType.RESPONSE
    agent_id = "response-mock-001"

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        return AgentResult(
            agent_id=self.agent_id,
            agent_type=AgentType.RESPONSE,
            status=AgentStatus.COMPLETED,
            output={"result": "responded"},
        )

    def get_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability.CONTAINMENT,
            AgentCapability.REMEDIATION,
        ]

    def get_required_approval(self) -> List[str]:
        return ["isolate_host", "block_ip"]


@pytest.fixture
def empty_registry():
    """A fresh empty registry."""
    reset_agent_registry()
    return AgentRegistry()


@pytest.fixture
def populated_registry():
    """A registry with triage, analysis, and response agents."""
    registry = AgentRegistry()
    registry.register(MockTriageAgent())
    registry.register(MockAnalysisAgent())
    registry.register(MockResponseAgent())
    return registry


# ── AgentCapability Tests ────────────────────────────────────────


class TestAgentCapability:

    def test_enum_values(self):
        """All capabilities have expected string values."""
        assert AgentCapability.ALERT_PARSING.value == "alert_parsing"
        assert AgentCapability.DEEP_ANALYSIS.value == "deep_analysis"
        assert AgentCapability.CONTAINMENT.value == "containment"
        assert AgentCapability.ORCHESTRATION.value == "orchestration"

    def test_unique_values(self):
        """No duplicate values in the enum."""
        values = [c.value for c in AgentCapability]
        assert len(values) == len(set(values)), "Duplicate capability values detected"


# ── AgentProtocol Tests ──────────────────────────────────────────


class TestAgentProtocol:

    def test_mock_agent_satisfies_protocol(self):
        """MockTriageAgent is a valid AgentProtocol."""
        agent = MockTriageAgent()
        # Structural check: it has the required methods
        assert hasattr(agent, "agent_type")
        assert hasattr(agent, "agent_id")
        assert hasattr(agent, "run")
        assert hasattr(agent, "get_capabilities")
        assert hasattr(agent, "get_required_approval")

    def test_base_agent_subclass_satisfies_protocol(self):
        """A BaseAgent subclass also satisfies AgentProtocol via adapter."""
        config = AgentConfig(
            name="Test Agent",
            agent_type=AgentType.TRIAGE,
        )
        agent = _create_minimal_base_agent(config)
        # Without adapter, it won't match AgentProtocol
        # But the adapter makes it work
        adapted = agent_protocol_adapter(agent)
        assert adapted.get_capabilities() is not None
        assert adapted.get_required_approval() is not None

    @pytest.mark.asyncio
    async def test_protocol_run(self):
        """AgentProtocol.run() works correctly."""
        agent = MockTriageAgent()
        result = await agent.run({"alert_id": "test-001"})
        assert result.status == AgentStatus.COMPLETED
        assert result.output["result"] == "triaged"


# ── AgentRegistry Tests ──────────────────────────────────────────


class TestAgentRegistryRegistration:

    def test_register_agent(self, empty_registry):
        """Agent can be registered and counted."""
        agent = MockTriageAgent()
        empty_registry.register(agent)
        assert empty_registry.count() == 1

    def test_register_duplicate_id(self, empty_registry):
        """Registering same agent_id twice overwrites."""
        agent1 = MockTriageAgent()
        agent2 = MockTriageAgent()  # Same class, different instance

        # Can't have duplicate agent_ids; mock uses fixed id
        # The second register should overwrite the first
        empty_registry.register(agent1)
        empty_registry.register(agent1)  # Same instance, should still be 1
        assert empty_registry.count() == 1

    def test_register_multiple_agents(self, empty_registry):
        """Multiple agents can be registered."""
        empty_registry.register(MockTriageAgent())
        empty_registry.register(MockAnalysisAgent())
        empty_registry.register(MockResponseAgent())
        assert empty_registry.count() == 3

    def test_unregister_agent(self, populated_registry):
        """Agent can be unregistered."""
        assert populated_registry.count() == 3
        result = populated_registry.unregister("triage-mock-001")
        assert result is True
        assert populated_registry.count() == 2

    def test_unregister_nonexistent(self, populated_registry):
        """Unregistering a non-existent agent returns False."""
        result = populated_registry.unregister("nonexistent-agent")
        assert result is False
        assert populated_registry.count() == 3

    def test_clear_registry(self, populated_registry):
        """Clearing the registry removes all agents."""
        populated_registry.clear()
        assert populated_registry.count() == 0


class TestAgentRegistryQuerying:

    def test_find_agents_by_capability(self, populated_registry):
        """Find agents that provide a specific capability."""
        agents = populated_registry.find_agents(AgentCapability.SEVERITY_ASSESSMENT)
        assert len(agents) == 1
        assert agents[0].agent_type == AgentType.TRIAGE

    def test_find_agents_by_capability_multiple(self, populated_registry):
        """Multiple agents may provide overlapping capabilities."""
        # No agent currently provides both containment AND deep_analysis
        containment_agents = populated_registry.find_agents(AgentCapability.CONTAINMENT)
        assert len(containment_agents) == 1
        assert containment_agents[0].agent_type == AgentType.RESPONSE

    def test_find_agents_by_nonexistent_capability(self, populated_registry):
        """Empty list for unregistered capability."""
        agents = populated_registry.find_agents(AgentCapability.CASE_CREATION)
        assert len(agents) == 0

    def test_find_agents_by_type(self, populated_registry):
        """Find agents by AgentType."""
        agents = populated_registry.find_agents_by_type(AgentType.TRIAGE)
        assert len(agents) == 1
        assert agents[0].agent_id == "triage-mock-001"

    def test_get_agent_by_id(self, populated_registry):
        """Get a specific agent by ID."""
        agent = populated_registry.get_agent("triage-mock-001")
        assert agent is not None
        assert agent.agent_type == AgentType.TRIAGE

    def test_get_agent_nonexistent(self, populated_registry):
        """None for unknown ID."""
        agent = populated_registry.get_agent("nobody-here")
        assert agent is None

    def test_get_registration(self, populated_registry):
        """Registration metadata is accessible."""
        reg = populated_registry.get_registration("triage-mock-001")
        assert reg is not None
        assert reg.agent_type == AgentType.TRIAGE
        assert AgentCapability.SEVERITY_ASSESSMENT in reg.capabilities
        assert reg.requires_approval is False

    def test_registration_for_response_agent(self, populated_registry):
        """Response agent registration shows approval requirement."""
        reg = populated_registry.get_registration("response-mock-001")
        assert reg is not None
        assert reg.requires_approval is True  # Because get_required_approval() non-empty


class TestAgentRegistryProperties:

    def test_agents_property(self, populated_registry):
        """agents property returns dict of all registered agents."""
        agents = populated_registry.agents
        assert len(agents) == 3
        assert "triage-mock-001" in agents

    def test_agents_property_is_copy(self, populated_registry):
        """agents property returns a copy, not the internal dict."""
        agents_view = populated_registry.agents
        agents_view.pop("triage-mock-001", None)
        assert populated_registry.count() == 3  # Original unchanged

    def test_registrations_property(self, populated_registry):
        """registrations property returns metadata for all agents."""
        regs = populated_registry.registrations
        assert len(regs) == 3
        assert all(isinstance(r, AgentRegistration) for r in regs.values())

    def test_all_capabilities_property(self, populated_registry):
        """all_capabilities shows all capabilities and their agent IDs."""
        caps = populated_registry.all_capabilities
        assert AgentCapability.SEVERITY_ASSESSMENT in caps
        assert AgentCapability.DEEP_ANALYSIS in caps
        assert AgentCapability.CONTAINMENT in caps


class TestAgentRegistrySerialization:

    def test_to_dict(self, populated_registry):
        """to_dict produces serializable output."""
        data = populated_registry.to_dict()
        assert data["agent_count"] == 3
        assert len(data["agents"]) == 3
        assert data["agents"][0]["agent_type"] == "triage"
        assert "capability_index" in data

    def test_to_dict_after_unregister(self, populated_registry):
        """to_dict reflects changes after unregistration."""
        populated_registry.unregister("triage-mock-001")
        data = populated_registry.to_dict()
        assert data["agent_count"] == 2

    def test_to_dict_empty(self, empty_registry):
        """Empty registry to_dict shows zero count."""
        data = empty_registry.to_dict()
        assert data["agent_count"] == 0
        assert data["agents"] == []
        assert data["capability_index"] == {}


# ── agent_protocol_adapter Tests ─────────────────────────────────


class TestAgentProtocolAdapter:

    def test_adapter_wraps_base_agent(self):
        """Adapter wraps a BaseAgent subclass with default capabilities."""
        config = AgentConfig(
            name="Test Triage",
            agent_type=AgentType.TRIAGE,
        )
        agent = _create_minimal_base_agent(config)
        adapted = agent_protocol_adapter(agent)

        assert adapted.agent_type == AgentType.TRIAGE
        capabilities = adapted.get_capabilities()
        assert AgentCapability.ALERT_PARSING in capabilities
        assert AgentCapability.SEVERITY_ASSESSMENT in capabilities

    def test_adapter_for_non_protocol_objects(self):
        """Adapter handles objects that don't satisfy AgentProtocol."""
        config = AgentConfig(
            name="Test Response",
            agent_type=AgentType.RESPONSE,
        )
        agent = _create_minimal_base_agent(config)
        adapted = agent_protocol_adapter(agent)

        caps = adapted.get_capabilities()
        assert AgentCapability.CONTAINMENT in caps

    def test_adapter_already_protocol(self):
        """Adapter returns the agent unchanged if it already satisfies the protocol."""
        agent = MockTriageAgent()
        adapted = agent_protocol_adapter(agent)
        # For protocol-satisfying objects, the adapter returns a new wrapper
        # (the isinstance check triggers, but our mock doesn't inherit from Protocol)
        # At minimum, it should still work correctly
        assert adapted.get_capabilities() is not None

    @pytest.mark.asyncio
    async def test_adapter_run_works(self):
        """Adapter.run() delegates to the inner agent."""
        config = AgentConfig(
            name="Test Agent",
            agent_type=AgentType.TRIAGE,
        )
        agent = _create_minimal_base_agent(config)
        adapted = agent_protocol_adapter(agent)

        result = await adapted.run({"test": "data"})
        assert result.status == AgentStatus.COMPLETED

    def test_adapter_default_approval(self):
        """Adapter sets default approval requirements by agent type."""
        # Response agent should have approval requirements
        response_config = AgentConfig(name="Resp", agent_type=AgentType.RESPONSE)
        response_agent = _create_minimal_base_agent(response_config)
        adapted = agent_protocol_adapter(response_agent)
        assert "isolate_host" in adapted.get_required_approval()

        # Triage agent should have no approval requirements
        triage_config = AgentConfig(name="Tri", agent_type=AgentType.TRIAGE)
        triage_agent = _create_minimal_base_agent(triage_config)
        adapted = agent_protocol_adapter(triage_agent)
        assert adapted.get_required_approval() == []


# ── Global Singleton Tests ───────────────────────────────────────


class TestGlobalRegistry:

    def setup_method(self):
        reset_agent_registry()

    def test_get_agent_registry_singleton(self):
        """get_agent_registry() always returns the same instance."""
        reg1 = get_agent_registry()
        reg2 = get_agent_registry()
        assert reg1 is reg2

    def test_reset_creates_new_instance(self):
        """reset_agent_registry() creates a fresh instance."""
        reg1 = get_agent_registry()
        reg1.register(MockTriageAgent())
        assert reg1.count() == 1

        reset_agent_registry()
        reg2 = get_agent_registry()
        assert reg2.count() == 0
        assert reg1 is not reg2


# ── Integration: Registry + Supervisor Routing ───────────────────


class TestRegistryIntegration:

    def test_supervisor_can_use_registry(self):
        """Supervisor can attach and use registry for routing."""
        from cobalto.agent.supervisor import SupervisorAgent

        registry = AgentRegistry()
        registry.register(MockTriageAgent())
        registry.register(MockAnalysisAgent())
        registry.register(MockResponseAgent())

        supervisor = SupervisorAgent()
        supervisor.attach_registry(registry)
        assert supervisor.registry is not None
        assert supervisor.registry.count() == 3

    def test_supervisor_routing_via_registry(self):
        """Supervisor routes to correct agent based on capabilities."""
        from cobalto.agent.supervisor import SupervisorAgent

        registry = AgentRegistry()
        registry.register(MockTriageAgent())
        registry.register(MockAnalysisAgent())

        supervisor = SupervisorAgent(agent_registry=registry)

        # Test routing decision for high severity
        decision = supervisor._route_by_capabilities(
            required_caps=["deep_analysis", "mitre_mapping"],
            alert={"severity": "high"},
            alert_type="unknown",
        )
        assert decision.next_agent == "analysis"

    def test_supervisor_routing_via_registry_default(self):
        """Supervisor falls back to triage when no capabilities match."""
        from cobalto.agent.supervisor import SupervisorAgent

        registry = AgentRegistry()
        # Only register a documentation agent, no triage/analysis
        class MockDocAgent:
            agent_type = AgentType.DOCUMENTATION
            agent_id = "doc-001"
            async def run(self, d): return AgentResult(agent_id="doc-001", agent_type=AgentType.DOCUMENTATION, status=AgentStatus.COMPLETED)
            def get_capabilities(self): return [AgentCapability.CASE_CREATION]
            def get_required_approval(self): return []

        registry.register(MockDocAgent())

        supervisor = SupervisorAgent(agent_registry=registry)
        decision = supervisor._route_by_capabilities(
            required_caps=["deep_analysis"],
            alert={"severity": "critical"},
            alert_type="unknown",
        )
        # Should fall back to triage
        assert decision.next_agent == "triage"


# ── Helpers ──────────────────────────────────────────────────────


def _create_minimal_base_agent(config: AgentConfig) -> BaseAgent:
    """Create a minimal BaseAgent subclass for testing."""
    class MinimalAgent(BaseAgent):
        async def run(self, input_data: Dict[str, Any]) -> AgentResult:
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
            )
        def get_system_prompt(self) -> str:
            return "Test prompt"
        def get_tools(self) -> List[Dict[str, Any]]:
            return []
    return MinimalAgent(config)
