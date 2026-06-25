"""
5-Layer Context Package for Silver Agents (DTP 3.4)

Each agent receives a structured context package, not raw log data.

CONTEXT LAYERS PER AGENT INVOCATION:

┌─────────────────────────────────────────────────────┐
│ 1. SEMANTIC CONTEXT                                  │
│    What business entities are involved?              │
│    asset_name, criticality, tenant_name, sla_tier   │
├─────────────────────────────────────────────────────┤
│ 2. OPERATIONAL CONTEXT                               │
│    What is the current state?                        │
│    normalized_event, prior_alerts_72h, open_cases    │
├─────────────────────────────────────────────────────┤
│ 3. INTELLIGENCE CONTEXT (RAG)                        │
│    What do we know about this threat?                │
│    top_k MITRE techniques, OpenCTI indicators        │
│    threat_actor_matches, CVE profiles                │
├─────────────────────────────────────────────────────┤
│ 4. POLICY CONTEXT                                    │
│    What is the agent allowed to do?                  │
│    allowed_actions[], autonomy_level, tenant_policy  │
├─────────────────────────────────────────────────────┤
│ 5. MEMORY CONTEXT                                    │
│    What happened before in this incident?            │
│    prior_agent_runs[], analyst_annotations[]         │
│    (Sliding window + summarization for long cases)   │
└─────────────────────────────────────────────────────┘
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import asyncio
import structlog

from .semantic import SemanticLayer
from .operational import OperationalLayer
from .intelligence import IntelligenceLayer
from .policy import PolicyLayer
from .memory import MemoryLayer

logger = structlog.get_logger(__name__)


class ContextPackage(BaseModel):
    """Structured context fed to each Silver agent invocation."""

    incident_id: str
    agent_type: str
    tenant_id: str
    semantic: Dict[str, Any] = {}
    operational: Dict[str, Any] = {}
    intelligence: Dict[str, Any] = {}
    policy: Dict[str, Any] = {}
    memory: Dict[str, Any] = {}
    assembled_at: datetime = Field(default_factory=datetime.utcnow)
    token_estimate: int = 0

    def to_prompt_context(self) -> str:
        """Convert context package to formatted string for agent prompts."""
        parts = []

        # Semantic context
        if self.semantic:
            parts.append(f"## Business Context\nTenant: {self.semantic.get('tenant_name', 'unknown')}")
            parts.append(f"SLA Tier: {self.semantic.get('sla_tier', 'standard')}")
            parts.append(f"Asset Criticality: {self.semantic.get('asset_criticality', 'unknown')}")

        # Operational context
        if self.operational:
            parts.append(f"\n## Operational Context")
            parts.append(f"Prior alerts (72h): {self.operational.get('alert_count_24h', 0)}")
            if self.operational.get('related_indicators'):
                parts.append(f"Related indicators: {', '.join(self.operational['related_indicators'][:5])}")

        # Intelligence context
        if self.intelligence:
            parts.append(f"\n## Threat Intelligence")
            techniques = self.intelligence.get('mitre_techniques', [])
            if techniques:
                parts.append(f"MITRE Techniques: {', '.join([t.get('technique_id', '') for t in techniques[:5]])}")
            parts.append(f"Confidence: {self.intelligence.get('confidence_score', 0):.2f}")

        # Policy context
        if self.policy:
            parts.append(f"\n## Policy Context")
            parts.append(f"Autonomy Level: {self.policy.get('autonomy_level', 'low')}")
            parts.append(f"Requires Approval: {self.policy.get('requires_approval', False)}")

        # Memory context
        if self.memory:
            parts.append(f"\n## Memory Context")
            if self.memory.get('summary'):
                parts.append(f"Summary: {self.memory['summary']}")
            recent = self.memory.get('recent_runs', [])
            if recent:
                parts.append(f"Recent runs: {len(recent)}")

        return "\n".join(parts)


class ContextBuilder:
    """Builds 5-layer context packages for Silver agents."""

    def __init__(
        self,
        qdrant_url: str = "http://localhost:6333",
        redis_url: str = "redis://localhost:6379",
        opencti_url: Optional[str] = None,
        opencti_token: Optional[str] = None,
    ):
        self.semantic = SemanticLayer()
        self.operational = OperationalLayer(redis_url)
        self.intelligence = IntelligenceLayer(qdrant_url, opencti_url, opencti_token)
        self.policy = PolicyLayer()
        self.memory = MemoryLayer(redis_url)

    async def build(
        self,
        incident_id: str,
        agent_type: str,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> ContextPackage:
        """Build complete context package for an agent."""
        logger.info(
            "building_context_package",
            incident_id=incident_id,
            agent_type=agent_type,
            tenant_id=tenant_id,
        )

        # Load all layers concurrently
        semantic, operational, intelligence, policy, memory = await asyncio.gather(
            self.semantic.load(tenant_id, alert_data),
            self.operational.load(incident_id),
            self.intelligence.load(incident_id, alert_data),
            self.policy.load(tenant_id, agent_type),
            self.memory.load(incident_id),
        )

        package = ContextPackage(
            incident_id=incident_id,
            agent_type=agent_type,
            tenant_id=tenant_id,
            semantic=semantic,
            operational=operational,
            intelligence=intelligence,
            policy=policy,
            memory=memory,
        )

        package.token_estimate = self._estimate_tokens(package)

        logger.info(
            "context_package_built",
            incident_id=incident_id,
            agent_type=agent_type,
            token_estimate=package.token_estimate,
        )

        return package

    def _estimate_tokens(self, package: ContextPackage) -> int:
        """Rough token estimate for budget management."""
        import json
        return len(json.dumps(package.model_dump())) // 3


# Convenience function
async def build_context(
    incident_id: str,
    agent_type: str,
    tenant_id: str,
    alert_data: Optional[Dict[str, Any]] = None,
    qdrant_url: str = "http://localhost:6333",
    redis_url: str = "redis://localhost:6379",
    opencti_url: Optional[str] = None,
    opencti_token: Optional[str] = None,
) -> ContextPackage:
    """Build context package for an agent."""
    builder = ContextBuilder(qdrant_url, redis_url, opencti_url, opencti_token)
    return await builder.build(incident_id, agent_type, tenant_id, alert_data)
