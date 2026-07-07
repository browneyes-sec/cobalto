"""Tests for the OSCAR orchestration engine."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from services.langgraph.agents.supervisor import (
    MagentaSupervisor,
    OSCARState,
    RoutingDecision,
)


class TestOSCARPhases:
    """Tests for OSCAR phase execution."""

    @pytest.mark.asyncio
    async def test_orient_to_strategize_transition(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="orient",
            alert_id="alert-123",
            tenant_id="tenant-1",
        )
        await supervisor._phase_orient({"severity": "high"})
        assert supervisor._state.phase == "strategize"

    @pytest.mark.asyncio
    async def test_critical_alert_goes_to_collect(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="strategize",
            alert_id="alert-123",
            tenant_id="tenant-1",
            triage_result={"severity": "critical", "alert_type": "ransomware"},
        )
        await supervisor._phase_strategize()
        assert supervisor._state.phase == "collect"

    @pytest.mark.asyncio
    async def test_medium_alert_goes_to_collect(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="strategize",
            alert_id="alert-123",
            tenant_id="tenant-1",
            triage_result={"severity": "medium", "alert_type": "scan"},
        )
        await supervisor._phase_strategize()
        assert supervisor._state.phase == "collect"

    @pytest.mark.asyncio
    async def test_low_severity_goes_to_report(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="strategize",
            alert_id="alert-123",
            tenant_id="tenant-1",
            triage_result={"severity": "informational", "alert_type": "info"},
        )
        await supervisor._phase_strategize()
        assert supervisor._state.phase == "report"

    @pytest.mark.asyncio
    async def test_collect_to_analyze(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="collect",
            alert_id="alert-123",
            tenant_id="tenant-1",
            triage_result={"severity": "high"},
        )
        await supervisor._phase_collect({"severity": "high"})
        assert supervisor._state.phase == "analyze"

    @pytest.mark.asyncio
    async def test_analyze_to_report(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="analyze",
            alert_id="alert-123",
            tenant_id="tenant-1",
            analysis_result={"patterns": ["ransomware"]},
        )
        await supervisor._phase_analyze({"severity": "high"})
        assert supervisor._state.phase == "report"

    @pytest.mark.asyncio
    async def test_report_to_complete(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="report",
            alert_id="alert-123",
            tenant_id="tenant-1",
            triage_result={"severity": "high"},
            analysis_result={"patterns": ["ransomware"]},
        )
        await supervisor._phase_report({"severity": "high"})
        assert supervisor._state.phase == "complete"

    @pytest.mark.asyncio
    async def test_execute_phase_tracks_history(self):
        supervisor = MagentaSupervisor()
        supervisor._state = OSCARState(
            phase="strategize",
            alert_id="alert-123",
            tenant_id="tenant-1",
            triage_result={"severity": "high"},
        )
        await supervisor._execute_phase({"severity": "high"})
        assert len(supervisor._state.history) == 1
        assert supervisor._state.history[0]["phase"] == "strategize"
        assert supervisor._state.history[0]["status"] == "completed"


class TestFullOrchestration:
    """Tests for full OSCAR orchestration flow."""

    @pytest.mark.asyncio
    async def test_orchestrate_critical_severity(self):
        supervisor = MagentaSupervisor()
        result = await supervisor.orchestrate(
            alert_id="alert-123",
            tenant_id="tenant-1",
            alert_data={"severity": "critical"},
        )
        assert result["status"] == "completed"
        assert result["alert_id"] == "alert-123"
        assert result["tenant_id"] == "tenant-1"
        assert result["triage_result"] is not None
        assert result["total_phases"] >= 4

    @pytest.mark.asyncio
    async def test_orchestrate_with_registered_agent(self):
        supervisor = MagentaSupervisor()
        mock_agent = MagicMock()
        mock_agent.run = AsyncMock(return_value=MagicMock(output={"severity": "high", "alert_type": "ransomware"}))
        supervisor.register_agent("silver-triage", mock_agent)
        result = await supervisor.orchestrate(
            alert_id="alert-456",
            tenant_id="tenant-1",
            alert_data={"severity": "critical"},
        )
        assert result["status"] == "completed"
        assert mock_agent.run.called

    @pytest.mark.asyncio
    async def test_orchestrate_collects_multiple_agents(self):
        supervisor = MagentaSupervisor()
        mock_triage = MagicMock()
        mock_triage.run = AsyncMock(return_value=MagicMock(output={"severity": "critical"}))
        mock_analysis = MagicMock()
        mock_analysis.run = AsyncMock(return_value=MagicMock(output={"patterns": ["ransomware"]}))
        supervisor.register_agent("silver-triage", mock_triage)
        supervisor.register_agent("silver-analysis", mock_analysis)
        result = await supervisor.orchestrate(
            alert_id="alert-789",
            tenant_id="tenant-1",
            alert_data={"severity": "critical"},
        )
        assert result["status"] == "completed"
        assert mock_triage.run.called
        assert mock_analysis.run.called

    @pytest.mark.asyncio
    async def test_orchestrate_handles_error_gracefully(self):
        supervisor = MagentaSupervisor()
        mock_agent = MagicMock()
        mock_agent.run = AsyncMock(side_effect=Exception("Simulated failure"))
        supervisor.register_agent("silver-triage", mock_agent)
        result = await supervisor.orchestrate(
            alert_id="alert-err",
            tenant_id="tenant-1",
            alert_data={"severity": "high"},
        )
        assert result["status"] == "completed"
        assert len(result.get("errors", [])) >= 1
        assert result["errors"][0] == "Phase orient failed: Simulated failure"

    @pytest.mark.asyncio
    async def test_orchestrate_all_phases_executed(self):
        supervisor = MagentaSupervisor()
        result = await supervisor.orchestrate(
            alert_id="alert-all",
            tenant_id="tenant-1",
            alert_data={"severity": "critical"},
        )
        phases = [h["phase"] for h in result["history"]]
        for phase in ["orient", "strategize", "collect", "analyze", "report"]:
            assert phase in phases, f"Phase {phase} was not executed"
