"""
Tool registry and base tool class for agent tools.
Provides a unified interface for defining and using tools.
"""

from typing import Any, Callable, Dict, List, Optional, Type
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool as LangChainBaseTool, tool
from langchain_core.callbacks import CallbackManagerForToolRun
from functools import wraps
import inspect


class ToolInput(BaseModel):
    """Base input schema for tools."""
    pass


class ToolOutput(BaseModel):
    """Base output schema for tools."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = {}


class ToolRegistry:
    """Registry for managing agent tools."""

    def __init__(self):
        self._tools: Dict[str, LangChainBaseTool] = {}
        self._tool_configs: Dict[str, Dict[str, Any]] = {}

    def register(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        args_schema: Optional[Type[BaseModel]] = None,
        return_direct: bool = False,
        tags: Optional[List[str]] = None,
    ) -> Callable:
        """Register a tool using decorator."""
        def decorator(func: Callable) -> Callable:
            tool_name = name or func.__name__
            tool_desc = description or func.__doc__ or f"Tool: {tool_name}"

            # Create LangChain tool
            lc_tool = tool(
                name=tool_name,
                description=tool_desc,
                args_schema=args_schema,
                return_direct=return_direct,
            )(func)

            # Store tool and metadata
            self._tools[tool_name] = lc_tool
            self._tool_configs[tool_name] = {
                "name": tool_name,
                "description": tool_desc,
                "tags": tags or [],
                "func": func,
            }

            return func

        return decorator

    def get_tool(self, name: str) -> Optional[LangChainBaseTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_tools(self, names: Optional[List[str]] = None) -> List[LangChainBaseTool]:
        """Get multiple tools by name."""
        if names:
            return [self._tools[name] for name in names if name in self._tools]
        return list(self._tools.values())

    def get_tools_by_tag(self, tag: str) -> List[LangChainBaseTool]:
        """Get tools by tag."""
        return [
            self._tools[name]
            for name, config in self._tool_configs.items()
            if tag in config.get("tags", [])
        ]

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools."""
        return [
            {
                "name": name,
                "description": config["description"],
                "tags": config["tags"],
            }
            for name, config in self._tool_configs.items()
        ]

    def has_tool(self, name: str) -> bool:
        """Check if a tool exists."""
        return name in self._tools

    def unregister(self, name: str) -> bool:
        """Unregister a tool."""
        if name in self._tools:
            del self._tools[name]
            del self._tool_configs[name]
            return True
        return False


# Global tool registry
_global_registry = ToolRegistry()


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry."""
    return _global_registry


def register_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    args_schema: Optional[Type[BaseModel]] = None,
    return_direct: bool = False,
    tags: Optional[List[str]] = None,
) -> Callable:
    """Decorator to register a tool globally."""
    return _global_registry.register(
        name=name,
        description=description,
        args_schema=args_schema,
        return_direct=return_direct,
        tags=tags,
    )


class BaseTool(LangChainBaseTool):
    """Base class for custom tools."""
    name: str
    description: str
    args_schema: Optional[Type[BaseModel]] = None
    return_direct: bool = False

    def _run(self, **kwargs: Any) -> Any:
        """Run the tool."""
        raise NotImplementedError

    async def _arun(self, **kwargs: Any) -> Any:
        """Async run the tool."""
        return self._run(**kwargs)


def tool_metadata(
    name: str,
    description: str,
    args_schema: Optional[Type[BaseModel]] = None,
    return_direct: bool = False,
    tags: Optional[List[str]] = None,
) -> Callable:
    """Decorator to add metadata to a tool."""
    def decorator(func: Callable) -> Callable:
        func.tool_name = name
        func.tool_description = description
        func.tool_args_schema = args_schema
        func.tool_return_direct = return_direct
        func.tool_tags = tags or []
        return func
    return decorator


def create_tool_from_function(
    func: Callable,
    name: Optional[str] = None,
    description: Optional[str] = None,
    args_schema: Optional[Type[BaseModel]] = None,
    return_direct: bool = False,
) -> LangChainBaseTool:
    """Create a LangChain tool from a function."""
    tool_name = name or func.__name__
    tool_desc = description or func.__doc__ or f"Tool: {tool_name}"

    return tool(
        name=tool_name,
        description=tool_desc,
        args_schema=args_schema,
        return_direct=return_direct,
    )(func)