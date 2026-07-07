"""
MCP Tool Registry - manages tool registration and invocation.
"""

from typing import Any, Callable, Dict, List, Optional, Type
from pydantic import BaseModel, Field
from functools import wraps
import inspect
import json

from cobalto.mcp.protocol import (
    MCPTool,
    MCPToolInputSchema,
    MCPToolCall,
    MCPToolCallResult,
    MCPTextContent,
    MCPErrorCode,
)


class MCPToolDefinition(BaseModel):
    """Internal tool definition with metadata."""
    name: str
    description: str
    func: Callable
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)
    requires_approval: bool = False
    timeout_seconds: int = 30


class ToolRegistry:
    """Registry for managing MCP tools."""

    def __init__(self):
        self._tools: Dict[str, MCPToolDefinition] = {}
        self._initialized = False

    def register(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        input_schema: Optional[Dict[str, Any]] = None,
        output_schema: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        requires_approval: bool = False,
        timeout_seconds: int = 30,
    ) -> Callable:
        """Register a tool using decorator."""
        def decorator(func: Callable) -> Callable:
            tool_name = name or func.__name__
            tool_desc = description or func.__doc__ or f"Tool: {tool_name}"

            # Build input schema from function signature if not provided
            if input_schema is None:
                schema = self._build_schema_from_function(func)
            else:
                schema = input_schema

            definition = MCPToolDefinition(
                name=tool_name,
                description=tool_desc,
                func=func,
                input_schema=schema,
                output_schema=output_schema,
                tags=tags or [],
                requires_approval=requires_approval,
                timeout_seconds=timeout_seconds,
            )

            self._tools[tool_name] = definition
            return func

        return decorator

    def _build_schema_from_function(self, func: Callable) -> Dict[str, Any]:
        """Build JSON Schema from function signature."""
        sig = inspect.signature(func)
        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            prop: Dict[str, Any] = {}

            # Get type annotation
            if param.annotation != inspect.Parameter.empty:
                prop["type"] = self._python_type_to_json_type(param.annotation)

            # Get default value
            if param.default != inspect.Parameter.empty:
                prop["default"] = param.default
            else:
                required.append(param_name)

            properties[param_name] = prop

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def _python_type_to_json_type(self, python_type: type) -> str:
        """Convert Python type to JSON Schema type."""
        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }
        return type_map.get(python_type, "string")

    def get_tool(self, name: str) -> Optional[MCPToolDefinition]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_mcp_tool(self, name: str) -> Optional[MCPTool]:
        """Get MCP tool representation."""
        definition = self._tools.get(name)
        if not definition:
            return None

        return MCPTool(
            name=definition.name,
            description=definition.description,
            inputSchema=MCPToolInputSchema(**definition.input_schema),
        )

    def list_tools(self) -> List[MCPTool]:
        """List all registered tools in MCP format."""
        return [
            MCPTool(
                name=defn.name,
                description=defn.description,
                inputSchema=MCPToolInputSchema(**defn.input_schema),
            )
            for defn in self._tools.values()
        ]

    def list_tool_names(self) -> List[str]:
        """List all tool names."""
        return list(self._tools.keys())

    def has_tool(self, name: str) -> bool:
        """Check if a tool exists."""
        return name in self._tools

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> MCPToolCallResult:
        """Call a tool by name."""
        definition = self._tools.get(name)
        if not definition:
            return MCPToolCallResult(
                content=[MCPTextContent(text=f"Tool not found: {name}")],
                isError=True,
            )

        try:
            # Call the function
            if inspect.iscoroutinefunction(definition.func):
                result = await definition.func(**(arguments or {}))
            else:
                result = definition.func(**(arguments or {}))

            # Convert result to MCP format
            if isinstance(result, MCPToolCallResult):
                return result

            # Convert to text content
            if isinstance(result, str):
                content = [MCPTextContent(text=result)]
            elif isinstance(result, dict):
                content = [MCPTextContent(text=json.dumps(result, default=str))]
            elif isinstance(result, list):
                content = [MCPTextContent(text=json.dumps(result, default=str))]
            else:
                content = [MCPTextContent(text=str(result))]

            return MCPToolCallResult(content=content)

        except Exception as e:
            return MCPToolCallResult(
                content=[MCPTextContent(text=f"Error: {str(e)}")],
                isError=True,
            )

    def get_tools_by_tag(self, tag: str) -> List[MCPTool]:
        """Get tools by tag."""
        return [
            MCPTool(
                name=defn.name,
                description=defn.description,
                inputSchema=MCPToolInputSchema(**defn.input_schema),
            )
            for defn in self._tools.values()
            if tag in defn.tags
        ]

    def unregister(self, name: str) -> bool:
        """Unregister a tool."""
        if name in self._tools:
            del self._tools[name]
            return True
        return False

    def clear(self) -> None:
        """Clear all registered tools."""
        self._tools.clear()


# Global tool registry
_global_tool_registry = ToolRegistry()


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry."""
    return _global_tool_registry


def mcp_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    input_schema: Optional[Dict[str, Any]] = None,
    output_schema: Optional[Dict[str, Any]] = None,
    tags: Optional[List[str]] = None,
    requires_approval: bool = False,
    timeout_seconds: int = 30,
) -> Callable:
    """Decorator to register an MCP tool globally."""
    return _global_tool_registry.register(
        name=name,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        tags=tags,
        requires_approval=requires_approval,
        timeout_seconds=timeout_seconds,
    )
