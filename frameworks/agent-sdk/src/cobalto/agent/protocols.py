"""
Context Builder Protocol — lightweight interface for context dependency injection.

Defined in agent-sdk to avoid circular imports between agent-sdk and context-engine.
Any object with a compatible `build()` method satisfies this protocol structurally.

Production implementation: cobalto.context.ports.ContextBuilder / ContextProvider
Test implementation:      cobalto.context.ports.MockContextBuilder
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class ContextBuilderProtocol(Protocol):
    """Protocol for context builders — structural typing, no import needed."""
    """Protocol for context builders — structural typing, no import needed.

    Any object with a `build()` method matching this signature can be
    injected into BaseAgent as its context provider.

    Usage:
        class MockBuilder:
            async def build(self, incident_id, agent_type, tenant_id, alert_data=None):
                return ContextPackage(...)

        agent = MyAgent(config, context_builder=MockBuilder())
        result = await agent.run(input_data)
    """

    async def build(
        self,
        incident_id: str,
        agent_type: str,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Build a context package for an agent invocation.

        Args:
            incident_id: Unique identifier for the incident/alert.
            agent_type: Type of agent requesting context.
            tenant_id: Tenant identifier for multi-tenant isolation.
            alert_data: Optional raw alert data for context enrichment.

        Returns:
            A context object (typically a ContextPackage from context-engine).
        """
        ...
