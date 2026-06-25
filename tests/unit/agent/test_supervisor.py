"""Tests for Magenta Supervisor."""

import pytest
from services.langgraph.agents.supervisor import MagentaSupervisor, OSCARState


class TestMagentaSupervisor:
    """Tests for MagentaSupervisor."""

    def test_supervisor_initialization(self):
        supervisor = MagentaSupervisor()
        assert supervisor.config.name == "Magenta Supervisor"
        assert supervisor._agents == {}

    def test_register_agent(self):
        supervisor = MagentaSupervisor()

        class MockAgent:
            pass

        agent = MockAgent()
        supervisor.register_agent("silver-triage", agent)
        assert "silver-triage" in supervisor._agents

    def test_oscar_state_initialization(self):
        state = OSCARState(
            phase="orient",
            alert_id="alert-123",
            tenant_id="tenant-1",
        )
        assert state.phase == "orient"
        assert state.alert_id == "alert-123"
        assert state.history == []
        assert state.errors == []

    def test_oscar_transitions(self):
        supervisor = MagentaSupervisor()
        assert "orient" in supervisor.OSCAR_TRANSITIONS
        assert "strategize" in supervisor.OSCAR_TRANSITIONS
        assert "collect" in supervisor.OSCAR_TRANSITIONS
        assert "analyze" in supervisor.OSCAR_TRANSITIONS
        assert "report" in supervisor.OSCAR_TRANSITIONS

    def test_phase_agents(self):
        supervisor = MagentaSupervisor()
        assert supervisor.PHASE_AGENTS["orient"] == "silver-triage"
        assert "silver-analysis" in supervisor.PHASE_AGENTS["collect"]
        assert "silver-intel" in supervisor.PHASE_AGENTS["collect"]

    def test_basic_triage(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="orient",
            alert_id="alert-123",
            tenant_id="tenant-1",
        )
        alert_data = {"severity": "high"}
        result = supervisor._basic_triage(alert_data)
        assert result["severity"] == "high"
        assert result["alert_id"] == "alert-123"

    def test_advance_phase(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="orient",
            alert_id="alert-123",
            tenant_id="tenant-1",
        )
        supervisor._advance_phase()
        assert supervisor._state.phase == "strategize"

    def test_compile_result(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="complete",
            alert_id="alert-123",
            tenant_id="tenant-1",
            triage_result={"severity": "high"},
            history=[{"phase": "orient", "status": "completed"}],
        )
        result = supervisor._compile_result()
        assert result["alert_id"] == "alert-123"
        assert result["status"] == "completed"
        assert result["triage_result"]["severity"] == "high"
        assert len(result["history"]) == 1
