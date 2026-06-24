"""
MCP Resource Registry - manages resource registration and retrieval.
"""

from typing import Any, Callable, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from functools import wraps
import inspect
import json

from cobalto.mcp.protocol import (
    MCPResource,
    MCPResourceTemplate,
    MCPResourceContents,
    MCPResourceReadResult,
    MCPErrorCode,
)


class MCPResourceDefinition(BaseModel):
    """Internal resource definition with metadata."""
    uri: str
    name: str
    description: str
    func: Callable
    mime_type: str = "application/json"
    is_template: bool = False
    uri_template: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class ResourceRegistry:
    """Registry for managing MCP resources."""

    def __init__(self):
        self._resources: Dict[str, MCPResourceDefinition] = {}
        self._templates: Dict[str, MCPResourceDefinition] = {}

    def register(
        self,
        uri: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        mime_type: str = "application/json",
        is_template: bool = False,
        uri_template: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Callable:
        """Register a resource using decorator."""
        def decorator(func: Callable) -> Callable:
            resource_name = name or func.__name__
            resource_desc = description or func.__doc__ or f"Resource: {resource_name}"

            definition = MCPResourceDefinition(
                uri=uri,
                name=resource_name,
                description=resource_desc,
                func=func,
                mime_type=mime_type,
                is_template=is_template,
                uri_template=uri_template or uri,
                tags=tags or [],
            )

            if is_template:
                self._templates[uri] = definition
            else:
                self._resources[uri] = definition

            return func

        return decorator

    def get_resource(self, uri: str) -> Optional[MCPResourceDefinition]:
        """Get a resource by URI."""
        return self._resources.get(uri)

    def get_template(self, uri: str) -> Optional[MCPResourceDefinition]:
        """Get a resource template by URI pattern."""
        return self._templates.get(uri)

    def match_template(self, uri: str) -> Optional[MCPResourceDefinition]:
        """Match a URI against registered templates."""
        for template_uri, definition in self._templates.items():
            if self._uri_matches_template(uri, template_uri):
                return definition
        return None

    def _uri_matches_template(self, uri: str, template: str) -> bool:
        """Check if a URI matches a template pattern."""
        # Simple pattern matching - replace {param} with regex
        import re
        pattern = re.sub(r'\{[^}]+\}', '[^/]+', template)
        pattern = f'^{pattern}$'
        return bool(re.match(pattern, uri))

    def list_resources(self) -> List[MCPResource]:
        """List all registered resources in MCP format."""
        return [
            MCPResource(
                uri=defn.uri,
                name=defn.name,
                description=defn.description,
                mimeType=defn.mime_type,
            )
            for defn in self._resources.values()
        ]

    def list_templates(self) -> List[MCPResourceTemplate]:
        """List all registered resource templates."""
        return [
            MCPResourceTemplate(
                uriTemplate=defn.uri_template or defn.uri,
                name=defn.name,
                description=defn.description,
                mimeType=defn.mime_type,
            )
            for defn in self._templates.values()
        ]

    def list_uris(self) -> List[str]:
        """List all resource URIs."""
        return list(self._resources.keys())

    def has_resource(self, uri: str) -> bool:
        """Check if a resource exists."""
        return uri in self._resources

    async def read_resource(self, uri: str) -> MCPResourceReadResult:
        """Read a resource by URI."""
        # First try exact match
        definition = self._resources.get(uri)

        # Then try template match
        if not definition:
            definition = self.match_template(uri)

        if not definition:
            return MCPResourceReadResult(
                contents=[
                    MCPResourceContents(
                        uri=uri,
                        text=f"Resource not found: {uri}",
                    )
                ]
            )

        try:
            # Call the function
            if inspect.iscoroutinefunction(definition.func):
                result = await definition.func(uri=uri)
            else:
                result = definition.func(uri=uri)

            # Convert to MCP format
            if isinstance(result, MCPResourceContents):
                contents = [result]
            elif isinstance(result, MCPResourceReadResult):
                contents = result.contents
            elif isinstance(result, str):
                contents = [
                    MCPResourceContents(
                        uri=uri,
                        mimeType=definition.mime_type,
                        text=result,
                    )
                ]
            elif isinstance(result, dict):
                contents = [
                    MCPResourceContents(
                        uri=uri,
                        mimeType=definition.mime_type,
                        text=json.dumps(result, default=str),
                    )
                ]
            elif isinstance(result, list):
                contents = [
                    MCPResourceContents(
                        uri=uri,
                        mimeType=definition.mime_type,
                        text=json.dumps(result, default=str),
                    )
                ]
            else:
                contents = [
                    MCPResourceContents(
                        uri=uri,
                        mimeType=definition.mime_type,
                        text=str(result),
                    )
                ]

            return MCPResourceReadResult(contents=contents)

        except Exception as e:
            return MCPResourceReadResult(
                contents=[
                    MCPResourceContents(
                        uri=uri,
                        text=f"Error reading resource: {str(e)}",
                    )
                ]
            )

    def unregister(self, uri: str) -> bool:
        """Unregister a resource."""
        if uri in self._resources:
            del self._resources[uri]
            return True
        return False

    def clear(self) -> None:
        """Clear all registered resources."""
        self._resources.clear()
        self._templates.clear()


# Global resource registry
_global_resource_registry = ResourceRegistry()


def get_resource_registry() -> ResourceRegistry:
    """Get the global resource registry."""
    return _global_resource_registry


def mcp_resource(
    uri: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    mime_type: str = "application/json",
    is_template: bool = False,
    uri_template: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Callable:
    """Decorator to register an MCP resource globally."""
    return _global_resource_registry.register(
        uri=uri,
        name=name,
        description=description,
        mime_type=mime_type,
        is_template=is_template,
        uri_template=uri_template,
        tags=tags,
    )
