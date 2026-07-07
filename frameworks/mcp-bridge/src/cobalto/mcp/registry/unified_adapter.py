"""
MCP ↔ UnifiedToolRegistry Adapter.

Bridges ``UnifiedToolRegistry`` (from agent-sdk) into the MCP bridge's
``ToolRegistry`` interface so the MCP server can consume a single source
of truth for tool definitions.

Usage::

    from cobalto.agent.tool_registry import get_tool_registry
    from cobalto.mcp.registry.unified_adapter import UnifiedMCPAdapter

    unified = get_tool_registry()
    adapter = UnifiedMCPAdapter(unified)

    # Pass to MCPServer directly
    server = MCPServer(tool_registry=adapter)

The adapter translates:
  - ``ToolDefinition`` → ``MCPTool`` / ``MCPToolDefinition``
  - ``UnifiedToolRegistry.execute()`` → ``MCPToolCallResult``
  - ``KeyError`` → ``MCPToolCallResult(isError=True)``
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Union

from cobalto.agent.tool_registry import (
    ToolDefinition,
    ToolRiskLevel,
    UnifiedToolRegistry,
)

from cobalto.mcp.protocol import (
    MCPTool,
    MCPToolInputSchema,
    MCPToolCallResult,
    MCPTextContent,
    MCPErrorCode,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Re-export the old ToolRegistry-compatible definition for callers that inspect
# the internal ``MCPToolDefinition`` type (e.g. the workflow tool).
# We keep it here as a simple data holder so ``UnifiedMCPAdapter.get_tool()``
# returns something that existing code can work with.
# ---------------------------------------------------------------------------

class MCPToolDefinition:
    """Lightweight stand-in for ``cobalto.mcp.registry.tools.MCPToolDefinition``.

    Returned by ``UnifiedMCPAdapter.get_tool()`` so existing consumers that
    access ``.name``, ``.description``, ``.input_schema`` etc. continue to work.
    """

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        func: Any = None,
        tags: Optional[List[str]] = None,
        requires_approval: bool = False,
        timeout_seconds: int = 30,
    ) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.func = func
        self.tags = tags or []
        self.requires_approval = requires_approval
        self.timeout_seconds = timeout_seconds


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class UnifiedMCPAdapter:
    """Wraps ``UnifiedToolRegistry`` in the ``ToolRegistry`` interface.

    The MCP server calls ``list_tools()``, ``call_tool()``, ``has_tool()``,
    etc. — this adapter translates to the unified registry under the hood.
    """

    def __init__(self, unified_registry: UnifiedToolRegistry) -> None:
        self._unified = unified_registry

    # -- Query helpers ---------------------------------------------------

    def list_tool_names(self) -> List[str]:
        """Return all registered tool names."""
        return self._unified.list_tool_names()

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered."""
        return self._unified.has_tool(name)

    def get_tool(self, name: str) -> Optional[MCPToolDefinition]:
        """Get internal tool representation."""
        defn = self._unified.get_definition(name)
        if defn is None:
            return None
        return MCPToolDefinition(
            name=defn.name,
            description=defn.description,
            input_schema=defn.parameters,
            func=None,  # executors are internal to UnifiedToolRegistry
            tags=defn.tags,
            requires_approval=defn.requires_approval,
            timeout_seconds=defn.timeout_seconds,
        )

    def get_tools_by_tag(self, tag: str) -> List[MCPTool]:
        """Get tools filtered by a tag, returned as MCP protocol objects."""
        defns = self._unified.find_tools_by_tag(tag)
        return [self._to_mcp_tool(d) for d in defns]

    # -- MCP protocol translation ---------------------------------------

    def list_tools(self) -> List[MCPTool]:
        """List all tools as MCP protocol objects (for ``tools/list``)."""
        return [self._to_mcp_tool(d) for d in self._unified.list_tools()]

    def get_mcp_tool(self, name: str) -> Optional[MCPTool]:
        """Get a single tool as an MCP protocol object."""
        defn = self._unified.get_definition(name)
        if defn is None:
            return None
        return self._to_mcp_tool(defn)

    async def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> MCPToolCallResult:
        """Execute a tool and return an MCP result (for ``tools/call``)."""
        try:
            result = await self._unified.execute(
                name=name,
                arguments=arguments or {},
                audit=True,
            )
            return self._to_mcp_result(result)

        except KeyError:
            return MCPToolCallResult(
                content=[MCPTextContent(text=f"Tool not found: {name}")],
                isError=True,
            )
        except Exception as exc:
            logger.exception("Tool %s failed", name)
            return MCPToolCallResult(
                content=[MCPTextContent(text=f"Error: {exc}")],
                isError=True,
            )

    # -- Registry management (delegated) ---------------------------------

    def unregister(self, name: str) -> bool:
        """Unregister a tool by name.

        Note: UnifiedToolRegistry does not support unregister. This is a
        best-effort removal from the registry's internal dicts.
        """
        # The UnifiedToolRegistry has no unregister method — this is a
        # no-op for now. If needed in the future, add it to the unified
        # registry.
        if not self._unified.has_tool(name):
            return False
        logger.warning("unregister(%s) is a no-op on UnifiedToolRegistry", name)
        return False

    def clear(self) -> None:
        """Clear the registry.

        Note: UnifiedToolRegistry does not support clear. This is a
        best-effort reset for testing contexts.
        """
        from cobalto.agent.tool_registry import reset_tool_registry
        reset_tool_registry()
        self._unified = get_tool_registry()

    # -- Internal helpers ------------------------------------------------

    @staticmethod
    def _to_mcp_tool(defn: ToolDefinition) -> MCPTool:
        """Convert a ``ToolDefinition`` into an ``MCPTool``."""
        return MCPTool(
            name=defn.name,
            description=defn.description,
            inputSchema=MCPToolInputSchema(
                type=defn.parameters.get("type", "object"),
                properties=defn.parameters.get("properties", {}),
                required=defn.parameters.get("required", []),
            ),
        )

    @staticmethod
    def _to_mcp_result(result: Any) -> MCPToolCallResult:
        """Wrap an arbitrary Python value in an ``MCPToolCallResult``."""
        if isinstance(result, MCPToolCallResult):
            return result

        if isinstance(result, str):
            content = [MCPTextContent(text=result)]
        elif isinstance(result, (dict, list)):
            content = [MCPTextContent(text=json.dumps(result, default=str))]
        else:
            content = [MCPTextContent(text=str(result))]

        return MCPToolCallResult(content=content)

    @staticmethod
    def tool_risk_to_mcp_error(risk: ToolRiskLevel) -> MCPErrorCode:
        """Map an internal risk level to an MCP error code (informational)."""
        # Not currently used but available for future approval gating.
        mapping = {
            ToolRiskLevel.LOW: MCPErrorCode.TOOL_NOT_FOUND,
            ToolRiskLevel.MEDIUM: MCPErrorCode.INVALID_TOOL_ARGUMENTS,
            ToolRiskLevel.HIGH: MCPErrorCode.TOOL_NOT_FOUND,
            ToolRiskLevel.CRITICAL: MCPErrorCode.TOOL_NOT_FOUND,
        }
        return mapping.get(risk, MCPErrorCode.TOOL_NOT_FOUND)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def get_unified_adapter() -> UnifiedMCPAdapter:
    """Create an adapter wrapping the global ``UnifiedToolRegistry`` singleton.

    This is the easiest way to wire the adapter into an MCP server::

        from cobalto.mcp.registry.unified_adapter import get_unified_adapter
        server = MCPServer(tool_registry=get_unified_adapter())
    """
    from cobalto.agent.tool_registry import get_tool_registry
    return UnifiedMCPAdapter(get_tool_registry())
