"""
Cobalto Context Engine - 5-Layer Context Model for Silver Agents

This package implements the 5-layer context engineering model defined in DTP 3.4.

Layers:
1. Semantic: Business entities (tenant, asset, SLA)
2. Operational: Current state (alerts, cases, velocity)
3. Intelligence: Threat intel via RAG (MITRE, OpenCTI)
4. Policy: Agent permissions and constraints
5. Memory: Prior runs with sliding window
"""

from .context_package import ContextBuilder, ContextPackage, build_context
from .semantic import SemanticLayer
from .operational import OperationalLayer
from .intelligence import IntelligenceLayer
from .policy import PolicyLayer
from .memory import MemoryLayer

__all__ = [
    "ContextBuilder",
    "ContextPackage",
    "build_context",
    "SemanticLayer",
    "OperationalLayer",
    "IntelligenceLayer",
    "PolicyLayer",
    "MemoryLayer",
]
