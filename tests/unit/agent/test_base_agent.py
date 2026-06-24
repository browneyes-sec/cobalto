"""
Unit tests for agent SDK.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, patch
from cobalto.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from cobalto.agent.state import AgentState, AlertState, Severity, AlertStatus
from cobalto.agent.supervisor import SupervisorAgent, RoutingDecision


class TestAgentConfig:
    """Test agent configuration."""

    def test_config_creation(self):
        """Test config creation."""
        config = AgentConfig(
            name="Test Agent",
            agent_type=AgentType.TRIAGE,
        )
        assert config.name == "Test Agent"
        assert config.agent_type == AgentType.TRIAGE
        assert config.model == "gpt-4o-mini"
        assert config.temperature == 0.1

    def test_config_validation(self):
        """Test config validation."""
        config = AgentConfig(
            name="Test Agent",
            agent_type=AgentType.ANALYSIS,
            model="gpt-4o",
            temperature=0.2,
        )
        assert config.model == "gpt-4o"
        assert config.temperature == 0.2


class TestAgentResult:
    """Test agent result."""

    def test_result_creation(self):
        """Test result creation."""
        result = AgentResult(
            agent_id="test-001",
            agent_type=AgentType.TRIAGE,
            status=AgentStatus.COMPLETED,
            output={"key": "value"},
        )
        assert result.agent_id == "test-001"
        assert result.status == AgentStatus.COMPLETED

    def test_result_to_dict(self):
        """Test result serialization."""
        result = AgentResult(
            agent_id="test-001",
            agent_type=AgentType.TRIAGE,
            status=AgentStatus.COMPLETED,
        )
        data = result.to_dict()
        assert data["agent_id"] == "test-001"


class TestBaseAgent:
    """Test base agent class."""

    def test_base_agent_creation(self):
        """Test base agent creation."""
        class TestAgent(BaseAgent):
            async def run(self, input_data):
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    status=AgentStatus.COMPLETED,
                )
            def get_system_prompt(self):
                return "Test prompt"
            def get_tools(self):
                return []

        config = AgentConfig(
            name="Test Agent",
            agent_type=AgentType.TRIAGE,
        )
        agent = TestAgent(config)
        assert agent.name == "Test Agent"
        assert agent.agent_type == AgentType.TRIAGE

    @pytest.mark.asyncio
    async def test_agent_run(self):
        """Test agent execution."""
        class TestAgent(BaseAgent):
            async def run(self, input_data):
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    status=AgentStatus.COMPLETED,
                    output={"result": "success"},
                )
            def get_system_prompt(self):
                return "Test prompt"
            def get_tools(self):
                return []

        config = AgentConfig(
            name="Test Agent",
            agent_type=AgentType.TRIAGE,
        )
        agent = TestAgent(config)
        result = await agent.run({"test": "data"})
        assert result.status == AgentStatus.COMPLETED
        assert result.output["result"] == "success"


class TestAgentState:
    """Test agent state."""

    def test_alert_state(self):
        """Test alert state creation."""
        state = AlertState(
            alert_id="alert-001",
            source="wazuh",
            severity=Severity.HIGH,
        )
        assert state.alert_id == "alert-001"
        assert state.severity == Severity.HIGH

    def test_severity_enum(self):
        """Test severity enum."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_alert_status(self):
        """Test alert status."""
        assert AlertStatus.NEW.value == "new"
        assert AlertStatus.TRIAGED.value == "triaged"


class TestSupervisor:
    """Test supervisor agent."""

    def test_supervisor_creation(self):
        """Test supervisor creation."""
        supervisor = SupervisorAgent()
        assert supervisor.name == "Supervisor Agent"
        assert supervisor.agent_type == AgentType.SUPERVISOR

    def test_register_agent(self):
        """Test agent registration."""
        supervisor = SupervisorAgent()
        supervisor.register_agent("triage", ["alert_parsing", "ioc_extraction"])
        assert "triage" in supervisor._agent_capabilities

    def test_routing_decision(self):
        """Test routing decision."""
        decision = RoutingDecision(
            next_agent="triage",
            reason="Default routing",
            confidence=0.8,
        )
        assert decision.next_agent == "triage"
        assert decision.confidence == 0.8

    @pytest.mark.asyncio
    async def test_supervisor_run(self):
        """Test supervisor execution."""
        supervisor = SupervisorAgent()
        supervisor.register_agent("triage", ["alert_parsing"])
        supervisor.register_agent("analysis", ["deep_analysis"])

        result = await supervisor.run({
            "alert_id": "alert-001",
            "alert": {
                "severity": "high",
                "source_ip": "203.0.113.45",
            },
        })
        assert result.status == AgentStatus.COMPLETED
        assert "routing" in result.output

    def test_determine_routing(self):
        """Test routing logic."""
        supervisor = SupervisorAgent()
        supervisor.register_agent("triage", ["alert_parsing"])
        supervisor.register_agent("analysis", ["deep_analysis"])

        # Test high severity routing
        decision = supervisor._determine_routing({
            "severity": "high",
            "source_ip": "203.0.113.45",
        })
        assert decision.next_agent == "analysis"

        # Test low severity routing
        decision = supervisor._determine_routing({
            "severity": "low",
        })
        assert decision.next_agent == "triage"