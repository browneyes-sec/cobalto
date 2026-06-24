"""
MCP Prompt Registry - manages prompt template registration and retrieval.
"""

from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field
from functools import wraps
import inspect

from cobalto.mcp.protocol import (
    MCPPrompt,
    MCPPromptArgument,
    MCPPromptMessage,
    MCPPromptResult,
    MCPTextContent,
    MCPErrorCode,
)


class MCPPromptDefinition(BaseModel):
    """Internal prompt definition with metadata."""
    name: str
    description: str
    func: Callable
    arguments: List[MCPPromptArgument] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class PromptRegistry:
    """Registry for managing MCP prompts."""

    def __init__(self):
        self._prompts: Dict[str, MCPPromptDefinition] = {}

    def register(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        arguments: Optional[List[Dict[str, Any]]] = None,
        tags: Optional[List[str]] = None,
    ) -> Callable:
        """Register a prompt using decorator."""
        def decorator(func: Callable) -> Callable:
            prompt_name = name or func.__name__
            prompt_desc = description or func.__doc__ or f"Prompt: {prompt_name}"

            # Build arguments from list of dicts
            prompt_arguments = []
            if arguments:
                for arg in arguments:
                    prompt_arguments.append(
                        MCPPromptArgument(
                            name=arg["name"],
                            description=arg.get("description"),
                            required=arg.get("required", False),
                        )
                    )

            definition = MCPPromptDefinition(
                name=prompt_name,
                description=prompt_desc,
                func=func,
                arguments=prompt_arguments,
                tags=tags or [],
            )

            self._prompts[prompt_name] = definition
            return func

        return decorator

    def get_prompt(self, name: str) -> Optional[MCPPromptDefinition]:
        """Get a prompt by name."""
        return self._prompts.get(name)

    def list_prompts(self) -> List[MCPPrompt]:
        """List all registered prompts in MCP format."""
        return [
            MCPPrompt(
                name=defn.name,
                description=defn.description,
                arguments=defn.arguments if defn.arguments else None,
            )
            for defn in self._prompts.values()
        ]

    def list_prompt_names(self) -> List[str]:
        """List all prompt names."""
        return list(self._prompts.keys())

    def has_prompt(self, name: str) -> bool:
        """Check if a prompt exists."""
        return name in self._prompts

    async def get_prompt(
        self,
        name: str,
        arguments: Optional[Dict[str, str]] = None,
    ) -> MCPPromptResult:
        """Get a prompt with arguments."""
        definition = self._prompts.get(name)
        if not definition:
            return MCPPromptResult(
                description=f"Prompt not found: {name}",
                messages=[
                    MCPPromptMessage(
                        role="user",
                        content=MCPTextContent(text=f"Prompt not found: {name}"),
                    )
                ],
            )

        try:
            # Call the function with arguments
            if inspect.iscoroutinefunction(definition.func):
                result = await definition.func(**(arguments or {}))
            else:
                result = definition.func(**(arguments or {}))

            # Convert to MCP format
            if isinstance(result, MCPPromptResult):
                return result

            # Convert string result to messages
            if isinstance(result, str):
                return MCPPromptResult(
                    description=definition.description,
                    messages=[
                        MCPPromptMessage(
                            role="user",
                            content=MCPTextContent(text=result),
                        )
                    ],
                )

            # Convert list of messages
            if isinstance(result, list):
                messages = []
                for msg in result:
                    if isinstance(msg, MCPPromptMessage):
                        messages.append(msg)
                    elif isinstance(msg, dict):
                        messages.append(
                            MCPPromptMessage(
                                role=msg.get("role", "user"),
                                content=MCPTextContent(text=msg.get("content", "")),
                            )
                        )
                    elif isinstance(msg, str):
                        messages.append(
                            MCPPromptMessage(
                                role="user",
                                content=MCPTextContent(text=msg),
                            )
                        )
                return MCPPromptResult(
                    description=definition.description,
                    messages=messages,
                )

            # Convert dict result
            if isinstance(result, dict):
                return MCPPromptResult(
                    description=definition.description,
                    messages=[
                        MCPPromptMessage(
                            role="user",
                            content=MCPTextContent(text=str(result)),
                        )
                    ],
                )

            # Default conversion
            return MCPPromptResult(
                description=definition.description,
                messages=[
                    MCPPromptMessage(
                        role="user",
                        content=MCPTextContent(text=str(result)),
                    )
                ],
            )

        except Exception as e:
            return MCPPromptResult(
                description=f"Error in prompt: {str(e)}",
                messages=[
                    MCPPromptMessage(
                        role="user",
                        content=MCPTextContent(text=f"Error: {str(e)}"),
                    )
                ],
            )

    def get_prompts_by_tag(self, tag: str) -> List[MCPPrompt]:
        """Get prompts by tag."""
        return [
            MCPPrompt(
                name=defn.name,
                description=defn.description,
                arguments=defn.arguments if defn.arguments else None,
            )
            for defn in self._prompts.values()
            if tag in defn.tags
        ]

    def unregister(self, name: str) -> bool:
        """Unregister a prompt."""
        if name in self._prompts:
            del self._prompts[name]
            return True
        return False

    def clear(self) -> None:
        """Clear all registered prompts."""
        self._prompts.clear()


# Global prompt registry
_global_prompt_registry = PromptRegistry()


def get_prompt_registry() -> PromptRegistry:
    """Get the global prompt registry."""
    return _global_prompt_registry


def mcp_prompt(
    name: Optional[str] = None,
    description: Optional[str] = None,
    arguments: Optional[List[Dict[str, Any]]] = None,
    tags: Optional[List[str]] = None,
) -> Callable:
    """Decorator to register an MCP prompt globally."""
    return _global_prompt_registry.register(
        name=name,
        description=description,
        arguments=arguments,
        tags=tags,
    )
