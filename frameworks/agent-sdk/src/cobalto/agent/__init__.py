"""
Cobalto Agent SDK
Base framework for building security AI agents using LangGraph.
"""

from .base_agent import BaseAgent, AgentConfig, AgentResult
from .state import AgentState, AlertState, InvestigationState
from .tools import ToolRegistry as LegacyToolRegistry, BaseTool, tool
from .memory import AgentMemory, ShortTermMemory, LongTermMemory
from .workflow import AgentWorkflow, WorkflowBuilder
from .supervisor import SupervisorAgent, RoutingDecision
from .prompts import PromptManager, PromptTemplate

# Phase 1 abstractions
from .registry import (
    AgentCapability,
    AgentProtocol,
    AgentRegistration,
    AgentRegistry,
    agent_protocol_adapter,
    get_agent_registry,
    reset_agent_registry,
)
from .tool_registry import (
    ToolDefinition,
    ToolRiskLevel,
    ToolCall,
    ToolExecutor,
    UnifiedToolRegistry,
    get_tool_registry as get_unified_tool_registry,
    reset_tool_registry as reset_unified_tool_registry,
)

# Phase 2 abstractions
from .protocols import ContextBuilderProtocol

__all__ = [
    # Existing
    "BaseAgent",
    "AgentConfig",
    "AgentResult",
    "AgentState",
    "AlertState",
    "InvestigationState",
    "LegacyToolRegistry",
    "BaseTool",
    "tool",
    "AgentMemory",
    "ShortTermMemory",
    "LongTermMemory",
    "AgentWorkflow",
    "WorkflowBuilder",
    "SupervisorAgent",
    "RoutingDecision",
    "PromptManager",
    "PromptTemplate",
    # New Phase 1
    "AgentCapability",
    "AgentProtocol",
    "AgentRegistration",
    "AgentRegistry",
    "agent_protocol_adapter",
    "get_agent_registry",
    "reset_agent_registry",
    "ToolDefinition",
    "ToolRiskLevel",
    "ToolCall",
    "ToolExecutor",
    "UnifiedToolRegistry",
    "get_unified_tool_registry",
    "reset_unified_tool_registry",
    # Phase 2
    "ContextBuilderProtocol",
]