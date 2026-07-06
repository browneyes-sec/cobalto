"""
Unified Tool Registry — single source of truth for tool definitions.

Provides:
- `ToolDefinition`: Pydantic model for tool metadata (name, description,
  JSON Schema parameters, risk level, approval requirement).
- `ToolExecutor`: Protocol for executing tools.
- `UnifiedToolRegistry`: Central registry consumed by both native agent
  runners and the MCP bridge, eliminating tool duplication.

This replaces the dual-tool-registry pattern (agent-sdk/tools.py AND
mcp-bridge/registry/tools.py) with a single source of truth.

Phase 1: Additive, non-breaking. The old registries continue to work.
Phase 2: Migrate consumers to UnifiedToolRegistry, deprecate old ones.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Set, Type, Union

from pydantic import BaseModel, Field


class ToolRiskLevel(str, Enum):
    """Risk level of a tool — used for approval gating."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolDefinition(BaseModel):
    """Complete definition of a tool.

    This is the single schema used by both:
    - Agent tool registries (for LLM function calling)
    - MCP bridge (for MCP tools/list and tools/call)
    """

    name: str
    description: str
    parameters: Dict[str, Any] = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {},
        },
        description="JSON Schema for tool parameters",
    )
    risk_level: ToolRiskLevel = ToolRiskLevel.LOW
    requires_approval: bool = False
    timeout_seconds: int = 30
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_openai_schema(self) -> Dict[str, Any]:
        """Convert to OpenAI function-calling schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_mcp_schema(self) -> Dict[str, Any]:
        """Convert to MCP tool schema (MCP spec)."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.parameters,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage/observability."""
        return self.model_dump()


class ToolCall(BaseModel):
    """A recorded tool execution — used for audit trail."""

    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    result: Any = None
    error: Optional[str] = None
    duration_seconds: float = 0.0
    requires_approval: bool = False
    approved: Optional[bool] = None
    approved_by: Optional[str] = None


class ToolExecutor(Protocol):
    """Protocol for executable tool implementations.

    Any callable or object with an `execute` method that satisfies this
    signature can be registered as a tool executor.
    """

    async def execute(self, arguments: Dict[str, Any]) -> Any:
        """Execute the tool with the given arguments."""
        ...


class AsyncToolWrapper:
    """Wraps a sync or async function as a ToolExecutor."""

    def __init__(self, func: Callable[..., Any]) -> None:
        self._func = func
        import inspect
        self._is_async = inspect.iscoroutinefunction(func)

    async def execute(self, arguments: Dict[str, Any]) -> Any:
        if self._is_async:
            return await self._func(**arguments)
        return self._func(**arguments)


class UnifiedToolRegistry:
    """Single registry for all tool definitions and executors.

    Consumption paths:
    - Native agents: `get_agent_tools(agent_type)` → filtered by tags
    - MCP bridge:   `list_mcp_tools()` → MCP-compatible schemas
    - Supervisor:   `find_tools_by_capability()` → capability-based

    This eliminates the dual-registry problem where tools were defined
    in both agent-sdk/tools.py and mcp-bridge/registry/tools.py.
    """

    def __init__(self) -> None:
        self._definitions: Dict[str, ToolDefinition] = {}
        self._executors: Dict[str, ToolExecutor] = {}
        self._capability_tags: Dict[str, Set[str]] = {}
        self._call_history: List[ToolCall] = []

    # ── Registration ──────────────────────────────────────────────

    def register(
        self,
        definition: ToolDefinition,
        executor: ToolExecutor,
        capabilities: Optional[List[str]] = None,
    ) -> str:
        """Register a tool with its definition and executor.

        Args:
            definition: Tool metadata including name, schema, risk level.
            executor: Callable that executes the tool.
            capabilities: Optional list of capability tags for discovery.

        Returns:
            The tool name (for chaining or immediate use).
        """
        name = definition.name
        self._definitions[name] = definition
        self._executors[name] = executor

        # Index by capability tags
        for tag in definition.tags:
            self._capability_tags.setdefault(tag, set()).add(name)
        for cap in (capabilities or []):
            self._capability_tags.setdefault(cap, set()).add(name)

        return name

    def register_function(
        self,
        func: Callable[..., Any],
        name: Optional[str] = None,
        description: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        risk_level: ToolRiskLevel = ToolRiskLevel.LOW,
        requires_approval: bool = False,
        timeout_seconds: int = 30,
        tags: Optional[List[str]] = None,
        capabilities: Optional[List[str]] = None,
    ) -> str:
        """Convenience: register a Python function as a tool.

        Args:
            func: The function to wrap.
            name: Tool name (defaults to func.__name__).
            description: Tool description (defaults to func.__doc__).
            parameters: JSON Schema for parameters (inferred if None).
            risk_level: Risk level for approval gating.
            requires_approval: Whether human approval is required.
            timeout_seconds: Execution timeout.
            tags: Tags for discovery/filtering.
            capabilities: Capability tags for agent routing.

        Returns:
            The tool name.
        """
        tool_name = name or func.__name__
        tool_desc = description or func.__doc__ or f"Tool: {tool_name}"

        # Infer JSON schema from function signature if not provided
        if parameters is None:
            parameters = self._infer_schema(func)

        definition = ToolDefinition(
            name=tool_name,
            description=tool_desc,
            parameters=parameters,
            risk_level=risk_level,
            requires_approval=requires_approval,
            timeout_seconds=timeout_seconds,
            tags=tags or [],
        )

        return self.register(definition, AsyncToolWrapper(func), capabilities)

    def _infer_schema(self, func: Callable[..., Any]) -> Dict[str, Any]:
        """Infer JSON Schema from a function's signature."""
        import inspect

        sig = inspect.signature(func)
        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            if param_name == "self" or param_name == "cls":
                continue

            # Determine type
            param_type = param.annotation if param.annotation != inspect.Parameter.empty else str
            json_type = self._python_type_to_json_type(param_type)
            properties[param_name] = {
                "type": json_type,
                "description": f"Parameter: {param_name}",
            }

            # Check for default
            if param.default == inspect.Parameter.empty:
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    @staticmethod
    def _python_type_to_json_type(py_type: Any) -> str:
        """Map Python types to JSON Schema types."""
        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            dict: "object",
            list: "array",
            type(None): "null",
        }
        # Handle Optional[X] → Union[X, None]
        origin = getattr(py_type, "__origin__", None)
        if origin is Union:
            args = py_type.__args__
            non_none = [a for a in args if a != type(None)]
            if non_none:
                return type_map.get(non_none[0], "string")
        return type_map.get(py_type, "string")

    # ── Querying ──────────────────────────────────────────────────

    def get_definition(self, name: str) -> Optional[ToolDefinition]:
        """Get a tool's definition by name."""
        return self._definitions.get(name)

    def get_executor(self, name: str) -> Optional[ToolExecutor]:
        """Get a tool's executor by name."""
        return self._executors.get(name)

    async def execute(
        self,
        name: str,
        arguments: Dict[str, Any],
        audit: bool = True,
    ) -> Any:
        """Execute a tool by name.

        Args:
            name: Tool name.
            arguments: Arguments to pass to the executor.
            audit: Whether to record the execution in the audit trail.

        Returns:
            The tool's result.

        Raises:
            KeyError: If the tool is not registered.
        """
        executor = self._executors.get(name)
        if executor is None:
            raise KeyError(f"Tool '{name}' is not registered")

        import time
        start = time.time()

        try:
            result = await executor.execute(arguments)
            duration = time.time() - start

            if audit:
                self._call_history.append(ToolCall(
                    tool_name=name,
                    arguments=arguments,
                    result=result,
                    duration_seconds=duration,
                ))
            return result

        except Exception as e:
            duration = time.time() - start

            if audit:
                self._call_history.append(ToolCall(
                    tool_name=name,
                    arguments=arguments,
                    error=str(e),
                    duration_seconds=duration,
                ))
            raise

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._definitions

    def list_tools(self) -> List[ToolDefinition]:
        """List all registered tool definitions."""
        return list(self._definitions.values())

    def list_tool_names(self) -> List[str]:
        """List all registered tool names."""
        return list(self._definitions.keys())

    # ── Filtered queries ──────────────────────────────────────────

    def find_tools_by_tag(self, tag: str) -> List[ToolDefinition]:
        """Find tools by tag."""
        names = self._capability_tags.get(tag, set())
        return [self._definitions[n] for n in names if n in self._definitions]

    def find_tools_by_capability(self, capability: str) -> List[ToolDefinition]:
        """Alias for find_tools_by_tag for semantic clarity."""
        return self.find_tools_by_tag(capability)

    def find_tools_by_risk(self, risk_level: ToolRiskLevel) -> List[ToolDefinition]:
        """Find tools at or above a risk level."""
        risk_order = {
            ToolRiskLevel.LOW: 0,
            ToolRiskLevel.MEDIUM: 1,
            ToolRiskLevel.HIGH: 2,
            ToolRiskLevel.CRITICAL: 3,
        }
        threshold = risk_order[risk_level]
        return [
            t for t in self._definitions.values()
            if risk_order.get(t.risk_level, 0) >= threshold
        ]

    def get_risk_level(self, name: str) -> Optional[ToolRiskLevel]:
        """Get the risk level of a tool."""
        definition = self._definitions.get(name)
        return definition.risk_level if definition else None

    def requires_approval(self, name: str) -> bool:
        """Check if a tool requires human approval."""
        definition = self._definitions.get(name)
        return definition.requires_approval if definition else False

    # ── MCP bridge export ─────────────────────────────────────────

    def list_mcp_tools(self) -> List[Dict[str, Any]]:
        """Export tool definitions in MCP schema format.

        Called by the MCP bridge to respond to tools/list requests.
        """
        return [t.to_mcp_schema() for t in self._definitions.values()]

    def list_openai_tools(self) -> List[Dict[str, Any]]:
        """Export tool definitions in OpenAI function-calling format.

        Called by agent runners for LLM tool binding.
        """
        return [t.to_openai_schema() for t in self._definitions.values()]

    # ── Agent-specific tool filtering ─────────────────────────────

    def get_agent_tools(
        self,
        agent_type: str,
        capability_tags: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Get tools filtered for a specific agent type.

        Args:
            agent_type: The agent type (e.g., "triage", "analysis").
            capability_tags: Additional capability tags to filter by.

        Returns:
            List of OpenAI-compatible tool schemas for the agent.
        """
        tags_to_match: Set[str] = {agent_type, *(capability_tags or [])}
        matched = set()
        for tag in tags_to_match:
            matched.update(self._capability_tags.get(tag, set()))
        return [
            self._definitions[name].to_openai_schema()
            for name in matched
            if name in self._definitions
        ]

    # ── Audit trail ───────────────────────────────────────────────

    @property
    def call_history(self) -> List[ToolCall]:
        """Immutable view of the execution audit trail."""
        return list(self._call_history)

    def clear_history(self) -> None:
        """Clear the audit trail (for testing or archival)."""
        self._call_history.clear()

    def get_recent_calls(self, n: int = 10) -> List[ToolCall]:
        """Get the most recent tool calls."""
        return self._call_history[-n:]

    # ── Status / introspection ────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize registry state for observability."""
        return {
            "tool_count": len(self._definitions),
            "tools": [
                {
                    "name": name,
                    "risk_level": defn.risk_level.value,
                    "requires_approval": defn.requires_approval,
                    "tags": defn.tags,
                }
                for name, defn in self._definitions.items()
            ],
            "capability_tags": {
                tag: list(names)
                for tag, names in self._capability_tags.items()
            },
            "total_executions": len(self._call_history),
        }


# ── Global singleton ──────────────────────────────────────────────

_global_registry: Optional[UnifiedToolRegistry] = None


def get_tool_registry() -> UnifiedToolRegistry:
    """Get the global UnifiedToolRegistry singleton."""
    global _global_registry
    if _global_registry is None:
        _global_registry = UnifiedToolRegistry()
    return _global_registry


def reset_tool_registry() -> None:
    """Reset the global registry (primarily for testing)."""
    global _global_registry
    _global_registry = UnifiedToolRegistry()
