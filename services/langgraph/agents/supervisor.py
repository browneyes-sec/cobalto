"""
Magenta Supervisor Agent

Orchestrates Silver agents using OSCAR framework:
O - Orient (Triage)
S - Strategize (Supervisor routing)
C - Collect (Analysis + Intel)
A - Analyze (Analysis)
R - Report (Documentation + Response)

Implements LangGraph state machine for agent coordination.
"""

from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field
from cobalto.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from cobalto.agent.state import InvestigationState, Severity
from cobalto.core.logging import get_logger
from cobalto.core.metrics import record_agent_execution
import time
import json

logger = get_logger(__name__)


class RoutingDecision(BaseModel):
    """Decision on how to route an alert."""
    next_agent: str
    reason: str
    confidence: float = Field(ge=0.0, le=1.0)
    priority: int = 0
    metadata: Dict[str, Any] = {}


class OSCARState(BaseModel):
    """OSCAR framework state."""
    phase: str = "orient"
    alert_id: str
    tenant_id: str
    triage_result: Optional[Dict[str, Any]] = None
    analysis_result: Optional[Dict[str, Any]] = None
    intel_result: Optional[Dict[str, Any]] = None
    response_result: Optional[Dict[str, Any]] = None
    documentation_result: Optional[Dict[str, Any]] = None
    current_agent: Optional[str] = None
    history: List[Dict[str, Any]] = []
    errors: List[str] = []


class MagentaSupervisor:
    """
    Magenta Supervisor for orchestrating Silver agents.

    Implements OSCAR framework for MDR investigations.
    """

    # OSCAR phase transitions
    OSCAR_TRANSITIONS = {
        "orient": ["strategize"],
        "strategize": ["collect", "report"],
        "collect": ["analyze"],
        "analyze": ["strategize", "report"],
        "report": ["complete"],
    }

    # Agent assignments per phase
    PHASE_AGENTS = {
        "orient": "silver-triage",
        "collect": ["silver-analysis", "silver-intel"],
        "analyze": "silver-analysis",
        "report": ["silver-docs", "silver-response"],
    }

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig(
            name="Magenta Supervisor",
            agent_type=AgentType.SUPERVISOR,
            description="Orchestrates Silver agents using OSCAR framework",
            model="gpt-4o",
            temperature=0.0,
        )
        self._agents: Dict[str, BaseAgent] = {}
        self._state: Optional[OSCARState] = None

    def register_agent(self, name: str, agent: BaseAgent) -> None:
        """Register a Silver agent."""
        self._agents[name] = agent
        logger.info("agent_registered", agent_name=name)

    async def orchestrate(
        self,
        alert_id: str,
        tenant_id: str,
        alert_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Orchestrate the full OSCAR workflow."""
        start_time = time.time()

        # Initialize state
        self._state = OSCARState(
            phase="orient",
            alert_id=alert_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "orchestration_started",
            alert_id=alert_id,
            tenant_id=tenant_id,
        )

        try:
            # Execute OSCAR phases
            while self._state.phase != "complete":
                await self._execute_phase(alert_data)

            duration = time.time() - start_time

            # Compile final result
            result = self._compile_result()

            logger.info(
                "orchestration_complete",
                alert_id=alert_id,
                duration=duration,
                phases=len(self._state.history),
            )

            return result

        except Exception as e:
            duration = time.time() - start_time
            logger.exception("orchestration_failed", error=str(e))
            return {
                "alert_id": alert_id,
                "status": "failed",
                "error": str(e),
                "duration": duration,
                "state": self._state.model_dump() if self._state else None,
            }

    async def _execute_phase(self, alert_data: Dict[str, Any]) -> None:
        """Execute the current OSCAR phase."""
        phase = self._state.phase

        logger.info("executing_phase", phase=phase, alert_id=self._state.alert_id)

        # Record phase start
        phase_start = {
            "phase": phase,
            "started_at": __import__("datetime").datetime.utcnow().isoformat(),
            "agent": self.PHASE_AGENTS.get(phase),
        }

        try:
            if phase == "orient":
                await self._phase_orient(alert_data)
            elif phase == "strategize":
                await self._phase_strategize()
            elif phase == "collect":
                await self._phase_collect(alert_data)
            elif phase == "analyze":
                await self._phase_analyze(alert_data)
            elif phase == "report":
                await self._phase_report(alert_data)
            else:
                logger.warning("unknown_phase", phase=phase)
                self._state.phase = "complete"

            phase_start["status"] = "completed"

        except Exception as e:
            phase_start["status"] = "failed"
            phase_start["error"] = str(e)
            self._state.errors.append(f"Phase {phase} failed: {str(e)}")
            logger.error("phase_failed", phase=phase, error=str(e))

            # Move to next phase or complete
            self._advance_phase()

        self._state.history.append(phase_start)

    async def _phase_orient(self, alert_data: Dict[str, Any]) -> None:
        """Orient phase: Initial alert triage."""
        self._state.phase = "orient"
        self._state.current_agent = "silver-triage"

        # Execute triage agent
        triage_agent = self._agents.get("silver-triage")
        if triage_agent:
            result = await triage_agent.run({
                "alert": alert_data,
                "alert_id": self._state.alert_id,
                "tenant_id": self._state.tenant_id,
            })
            self._state.triage_result = result.output
        else:
            # Fallback: basic triage
            self._state.triage_result = self._basic_triage(alert_data)

        self._advance_phase()

    async def _phase_strategize(self) -> None:
        """Strategize phase: Determine next steps."""
        self._state.phase = "strategize"
        self._state.current_agent = "supervisor"

        # Analyze triage result to determine routing
        triage = self._state.triage_result or {}
        severity = triage.get("severity", "informational")
        alert_type = triage.get("alert_type", "unknown")

        # Determine next phase based on severity
        if severity in ("critical", "high"):
            # Need deep analysis
            self._state.phase = "collect"
        elif severity == "medium":
            # Need threat intel correlation
            self._state.phase = "collect"
        else:
            # Low severity, go to report
            self._state.phase = "report"

        logger.info(
            "strategize_complete",
            severity=severity,
            next_phase=self._state.phase,
        )

    async def _phase_collect(self, alert_data: Dict[str, Any]) -> None:
        """Collect phase: Gather evidence from multiple sources."""
        self._state.phase = "collect"
        self._state.current_agent = "silver-analysis"

        # Execute analysis agent
        analysis_agent = self._agents.get("silver-analysis")
        if analysis_agent:
            result = await analysis_agent.run({
                "alert": alert_data,
                "alert_id": self._state.alert_id,
                "tenant_id": self._state.tenant_id,
                "triage_result": self._state.triage_result,
            })
            self._state.analysis_result = result.output

        # Execute intel agent if available
        intel_agent = self._agents.get("silver-intel")
        if intel_agent:
            result = await intel_agent.run({
                "alert": alert_data,
                "alert_id": self._state.alert_id,
                "tenant_id": self._state.tenant_id,
                "triage_result": self._state.triage_result,
            })
            self._state.intel_result = result.output

        self._advance_phase()

    async def _phase_analyze(self, alert_data: Dict[str, Any]) -> None:
        """Analyze phase: Interpret patterns and assess risk."""
        self._state.phase = "analyze"
        self._state.current_agent = "silver-analysis"

        # Analysis already done in collect phase
        # This phase validates and enriches the analysis
        if self._state.analysis_result:
            # Add risk assessment if not present
            if "risk_assessment" not in self._state.analysis_result:
                self._state.analysis_result["risk_assessment"] = {
                    "risk_score": 50,
                    "risk_level": "medium",
                    "risk_factors": ["Automated assessment"],
                }

        self._advance_phase()

    async def _phase_report(self, alert_data: Dict[str, Any]) -> None:
        """Report phase: Generate documentation and response plan."""
        self._state.phase = "report"
        self._state.current_agent = "silver-response"

        # Execute response agent
        response_agent = self._agents.get("silver-response")
        if response_agent:
            result = await response_agent.run({
                "alert": alert_data,
                "alert_id": self._state.alert_id,
                "tenant_id": self._state.tenant_id,
                "analysis_result": self._state.analysis_result,
                "triage_result": self._state.triage_result,
            })
            self._state.response_result = result.output

        # Execute documentation agent if available
        docs_agent = self._agents.get("silver-docs")
        if docs_agent:
            result = await docs_agent.run({
                "alert": alert_data,
                "alert_id": self._state.alert_id,
                "tenant_id": self._state.tenant_id,
                "triage_result": self._state.triage_result,
                "analysis_result": self._state.analysis_result,
                "response_result": self._state.response_result,
            })
            self._state.documentation_result = result.output

        # Mark as complete
        self._state.phase = "complete"

    def _advance_phase(self) -> None:
        """Advance to next phase based on current phase."""
        current = self._state.phase
        transitions = self.OSCAR_TRANSITIONS.get(current, ["complete"])
        if transitions:
            self._state.phase = transitions[0]
        else:
            self._state.phase = "complete"

    def _basic_triage(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Basic triage fallback."""
        severity = alert_data.get("severity", "informational")
        return {
            "alert_id": self._state.alert_id,
            "alert_type": "unknown",
            "severity": severity,
            "indicators": [],
            "confidence": 0.5,
        }

    def _compile_result(self) -> Dict[str, Any]:
        """Compile final orchestration result."""
        return {
            "alert_id": self._state.alert_id,
            "tenant_id": self._state.tenant_id,
            "status": "completed",
            "triage_result": self._state.triage_result,
            "analysis_result": self._state.analysis_result,
            "intel_result": self._state.intel_result,
            "response_result": self._state.response_result,
            "documentation_result": self._state.documentation_result,
            "history": self._state.history,
            "errors": self._state.errors,
            "total_phases": len(self._state.history),
        }


# Convenience function
async def run_orchestration(
    alert_id: str,
    tenant_id: str,
    alert_data: Dict[str, Any],
    agents: Optional[Dict[str, BaseAgent]] = None,
) -> Dict[str, Any]:
    """Run the full OSCAR orchestration."""
    supervisor = MagentaSupervisor()

    # Register agents
    if agents:
        for name, agent in agents.items():
            supervisor.register_agent(name, agent)

    return await supervisor.orchestrate(alert_id, tenant_id, alert_data)
