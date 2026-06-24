"""
Cobalto MCP Bridge - Model Context Protocol implementation for the Agentic SOC platform.

Exposes Cobalto agents, tools, and resources via MCP for external integration.
"""

from cobalto.mcp.protocol import (
    JSONRPCMessage,
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCError,
    MCPMethod,
    MCPCapabilities,
    MCPTool,
    MCPResource,
    MCPPrompt,
    MCPTextContent,
    MCPImageContent,
    MCPEmbeddedResource,
    MCPToolCallResult,
    MCPResourceContents,
    MCPInitializeParams,
    MCPInitializeResult,
)
from cobalto.mcp.server import MCPServer
from cobalto.mcp.registry.tools import ToolRegistry, mcp_tool
from cobalto.mcp.registry.resources import ResourceRegistry, mcp_resource
from cobalto.mcp.registry.prompts import PromptRegistry, mcp_prompt

__all__ = [
    # Protocol types
    "JSONRPCMessage",
    "JSONRPCRequest",
    "JSONRPCResponse",
    "JSONRPCError",
    "MCPMethod",
    "MCPCapabilities",
    "MCPTool",
    "MCPResource",
    "MCPPrompt",
    "MCPTextContent",
    "MCPImageContent",
    "MCPEmbeddedResource",
    "MCPToolCallResult",
    "MCPResourceContents",
    "MCPInitializeParams",
    "MCPInitializeResult",
    # Server
    "MCPServer",
    # Registries
    "ToolRegistry",
    "ResourceRegistry",
    "PromptRegistry",
    "mcp_tool",
    "mcp_resource",
    "mcp_prompt",
]
