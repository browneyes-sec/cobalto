"""
Base agent class for all Cobalto security AI agents.
Provides the foundation for LangGraph-based agent workflows.

Supports optional context injection via ContextBuilderProtocol.
When no context_builder is provided, agents fall back to the
production ContextBuilder from context-engine (backward compatible).

See cobalto.agent.protocols.ContextBuilderProtocol for the interface.
"""

import uuid
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable
from pydantic import BaseModel, Field
from enum import Enum


class AgentType(str, Enum):
    TRIAGE = "triage"
    ANALYSIS = "analysis"
    THREAT_INTEL = "threat_intel"
    RESPONSE = "response"
    THREAT_HUNT = "threat_hunt"
    DOCUMENTATION = "documentation"
    SUPERVISOR = "supervisor"


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentConfig(BaseModel):
    """Configuration for an agent."""
    name: str
    agent_type: AgentType
    description: str = ""
    model: str = "gpt-4o-mini"
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout_seconds: int = 300
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    tools: List[str] = []
    allowed_action_types: List[str] = []
    requires_approval: bool = False
    priority: int = 0
    metadata: Dict[str, Any] = {}

    model_config = {"use_enum_values": False}


class AgentResult(BaseModel):
    """Result from an agent execution."""
    agent_id: str
    agent_type: AgentType
    status: AgentStatus
    output: Dict[str, Any] = {}
    error: Optional[str] = None
    duration_seconds: float = 0.0
    token_usage: Dict[str, int] = {}
    metadata: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class BaseAgent(ABC):
    """Base class for all Cobalto security AI agents.

    Supports optional context injection:
        agent = MyAgent(config, context_builder=my_builder)
        ctx = await agent.build_context("inc-001", "triage", "tenant-1")

    When no context_builder is provided, build_context() falls back
    to the production ContextBuilder from context-engine.
    """

    def __init__(
        self,
        config: AgentConfig,
        context_builder: Optional[Any] = None,
    ):
        self.config = config
        self.agent_id = f"{config.agent_type.value}-{uuid.uuid4().hex[:8]}"
        self.status = AgentStatus.IDLE
        self._execution_count = 0
        self._total_duration = 0.0
        self._context_builder = context_builder

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def agent_type(self) -> AgentType:
        return self.config.agent_type

    @abstractmethod
    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute the agent logic."""
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        pass

    @abstractmethod
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get the tools available to this agent."""
        pass

    async def __call__(self, input_data: Dict[str, Any]) -> AgentResult:
        """Make the agent callable."""
        return await self.run(input_data)

    # ── Context injection support ────────────────────────────────

    async def build_context(
        self,
        incident_id: str,
        agent_type: str,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Build 5-layer context for this agent invocation.

        Uses the injected context_builder if available, otherwise
        falls back to the production ContextBuilder from context-engine.

        Args:
            incident_id: Unique identifier for the incident/alert.
            agent_type: Type of agent requesting context.
            tenant_id: Tenant identifier for multi-tenant isolation.
            alert_data: Optional raw alert data for context enrichment.

        Returns:
            ContextPackage with semantic, operational, intelligence,
            policy, and memory layers populated.
        """
        if self._context_builder is not None:
            return await self._context_builder.build(
                incident_id=incident_id,
                agent_type=agent_type,
                tenant_id=tenant_id,
                alert_data=alert_data,
            )

        # Fallback to production ContextBuilder
        from cobalto.context.context_package import build_context  # type: ignore[import-untyped]
        return await build_context(
            incident_id=incident_id,
            agent_type=agent_type,
            tenant_id=tenant_id,
            alert_data=alert_data,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.config.agent_type.value,
            "execution_count": self._execution_count,
            "total_duration_seconds": self._total_duration,
            "avg_duration_seconds": (
                self._total_duration / self._execution_count
                if self._execution_count > 0
                else 0
            ),
        }