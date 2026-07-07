"""
Context Ports — interface definitions for the 5-layer context model.

Provides:
- `ContextPort`: Abstract base class / Protocol for context retrieval.
  Enables dependency injection of context implementations, making agents
  testable without real infrastructure (Qdrant, Redis, OpenCTI).

- `ContextProvider`: Higher-level service interface for agent consumption.
  Agents receive a ContextProvider, not a concrete ContextBuilder.

This is Phase 1 of the evolvability roadmap. It introduces zero breaking
changes: existing ContextBuilder usage continues to work unchanged.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from .context_package import ContextPackage


class ContextPort(ABC):
    """Abstract interface for context retrieval.

    Implementations:
    - `ContextBuilder` (existing) — the production implementation that
      loads layers from Qdrant, Redis, OpenCTI, etc.
    - `MockContextBuilder` — for testing, returns canned data.
    - `CachedContextBuilder` — wraps another port with caching.
    - `RemoteContextPort` — gRPC/HTTP client for Phase 3 service split.

    Usage in agents (after Phase 2 constructor injection):
        class MyAgent(BaseAgent):
            def __init__(self, config, context_port: ContextPort):
                self.context_port = context_port
                ...

            async def run(self, input_data):
                ctx = await self.context_port.build(
                    incident_id=...,
                    agent_type="triage",
                    tenant_id=...,
                    alert_data=...,
                )
    """

    @abstractmethod
    async def build(
        self,
        incident_id: str,
        agent_type: str,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> ContextPackage:
        """Build a complete 5-layer context package for an agent.

        Args:
            incident_id: Unique identifier for the incident/alert.
            agent_type: Type of agent requesting context (e.g., "triage").
            tenant_id: Tenant identifier (for multi-tenant isolation).
            alert_data: Optional raw alert data for context enrichment.

        Returns:
            A fully assembled ContextPackage with all 5 layers populated.
        """
        ...


@runtime_checkable
class ContextProtocol(Protocol):
    """Structural protocol for context providers.

    Enables duck-typing: any object with a `build` method matching this
    signature can be used as a context provider without inheriting from
    ContextPort.
    """

    async def build(
        self,
        incident_id: str,
        agent_type: str,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> ContextPackage:
        ...


class ContextProvider:
    """Higher-level context service for agent consumption.

    Wraps a ContextPort and provides:
    - Agent-specific context trimming (only relevant layers)
    - Token budget management
    - Caching (optional, phase 2)
    - Observability hooks

    Agents use this instead of calling ContextPort directly.
    """

    def __init__(
        self,
        port: ContextPort,
        max_context_tokens: int = 8000,
    ) -> None:
        self._port = port
        self._max_context_tokens = max_context_tokens

    async def build(
        self,
        incident_id: str,
        agent_type: str,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> ContextPackage:
        """Build context, respecting token budget."""
        package = await self._port.build(
            incident_id=incident_id,
            agent_type=agent_type,
            tenant_id=tenant_id,
            alert_data=alert_data,
        )

        # Trim if over budget
        if package.token_estimate > self._max_context_tokens:
            package = self._trim_context(package)

        return package

    def _trim_context(self, package: ContextPackage) -> ContextPackage:
        """Remove low-priority context layers to fit token budget."""
        # Priority order: policy > intelligence > operational > memory > semantic
        # Remove layers lowest priority first
        if package.token_estimate <= self._max_context_tokens:
            return package

        if package.memory and package.token_estimate > self._max_context_tokens:
            package.memory = {"trimmed": True, "original_size": len(str(package.memory))}

        if package.semantic and package.token_estimate > self._max_context_tokens:
            package.semantic = {"tenant_name": package.semantic.get("tenant_name", "unknown")}

        return package


class MockContextBuilder(ContextPort):
    """Mock context port for testing — returns canned data.

    Usage in tests:
        context_port = MockContextBuilder(canned_data={
            "semantic": {"tenant_name": "acme-corp", "asset_criticality": "high"},
            "policy": {"autonomy_level": "high"},
        })
        agent = MyAgent(config, context_port)
        result = await agent.run(input_data)
    """

    def __init__(
        self,
        canned_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.canned_data = canned_data or {}

    async def build(
        self,
        incident_id: str,
        agent_type: str,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> ContextPackage:
        """Return a context package with canned data."""
        return ContextPackage(
            incident_id=incident_id,
            agent_type=agent_type,
            tenant_id=tenant_id,
            semantic=self.canned_data.get("semantic", {}),
            operational=self.canned_data.get("operational", {}),
            intelligence=self.canned_data.get("intelligence", {}),
            policy=self.canned_data.get("policy", {}),
            memory=self.canned_data.get("memory", {}),
        )


# ── Convenience factory ───────────────────────────────────────────

def create_context_provider(
    qdrant_url: str = "http://localhost:6333",
    redis_url: str = "redis://localhost:6379",
    opencti_url: Optional[str] = None,
    opencti_token: Optional[str] = None,
    max_context_tokens: int = 8000,
) -> ContextProvider:
    """Create a production ContextProvider backed by ContextBuilder.

    This is a convenience factory that wires up the default production
    implementation. For testing, use MockContextBuilder directly.

    Example:
        provider = create_context_provider()
        ctx = await provider.build(incident_id="i-123", agent_type="triage", ...)
    """
    from .context_package import ContextBuilder

    port = ContextBuilder(
        qdrant_url=qdrant_url,
        redis_url=redis_url,
        opencti_url=opencti_url,
        opencti_token=opencti_token,
    )
    return ContextProvider(port=port, max_context_tokens=max_context_tokens)
