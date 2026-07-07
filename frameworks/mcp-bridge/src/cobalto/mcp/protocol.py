"""
MCP Protocol types implementing JSON-RPC 2.0 for Model Context Protocol.

Reference: https://spec.modelcontextprotocol.io/specification/2024-11-05/
"""

from typing import Any, Dict, List, Optional, Union
from enum import Enum
from pydantic import BaseModel, Field
import uuid


# =============================================================================
# JSON-RPC Types
# =============================================================================

class JSONRPCMessage(BaseModel):
    """Base JSON-RPC 2.0 message."""
    jsonrpc: str = "2.0"


class JSONRPCRequest(JSONRPCMessage):
    """JSON-RPC 2.0 request."""
    id: Union[str, int] = Field(default_factory=lambda: str(uuid.uuid4()))
    method: str
    params: Optional[Dict[str, Any]] = None


class JSONRPCResponse(JSONRPCMessage):
    """JSON-RPC 2.0 response."""
    id: Union[str, int]
    result: Optional[Any] = None
    error: Optional["JSONRPCError"] = None


class JSONRPCError(BaseModel):
    """JSON-RPC 2.0 error object."""
    code: int
    message: str
    data: Optional[Any] = None


class JSONRPCNotification(JSONRPCMessage):
    """JSON-RPC 2.0 notification (no id)."""
    method: str
    params: Optional[Dict[str, Any]] = None


# =============================================================================
# MCP Protocol Version
# =============================================================================

MCP_PROTOCOL_VERSION = "2024-11-05"


# =============================================================================
# MCP Method Names
# =============================================================================

class MCPMethod(str, Enum):
    """MCP method names."""
    # Lifecycle
    INITIALIZE = "initialize"
    INITIALIZED = "notifications/initialized"
    PING = "ping"

    # Tools
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"

    # Resources
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    RESOURCES_TEMPLATES_LIST = "resources/templates/list"
    RESOURCES_SUBSCRIBE = "resources/subscribe"
    RESOURCES_UNSUBSCRIBE = "resources/unsubscribe"

    # Prompts
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"

    # Sampling
    SAMPLING_CREATE_MESSAGE = "sampling/createMessage"

    # Roots
    ROOTS_LIST = "roots/list"
    ROOTS_CHANGED = "notifications/roots/list_changed"

    # Logging
    LOGGING_SET_LEVEL = "logging/setLevel"


# =============================================================================
# MCP Capabilities
# =============================================================================

class MCPServerCapabilities(BaseModel):
    """Capabilities supported by the MCP server."""
    tools: Optional[Dict[str, Any]] = Field(default_factory=dict)
    resources: Optional[Dict[str, Any]] = Field(default_factory=dict)
    prompts: Optional[Dict[str, Any]] = Field(default_factory=dict)
    logging: Optional[Dict[str, Any]] = Field(default_factory=dict)
    sampling: Optional[Dict[str, Any]] = Field(default_factory=dict)
    roots: Optional[Dict[str, Any]] = Field(default_factory=dict)


class MCPClientCapabilities(BaseModel):
    """Capabilities supported by the MCP client."""
    roots: Optional[Dict[str, Any]] = Field(default_factory=None)
    sampling: Optional[Dict[str, Any]] = Field(default_factory=None)


class MCPCapabilities(BaseModel):
    """MPC capabilities exchange."""
    tools: Optional[Dict[str, Any]] = Field(default_factory=dict)
    resources: Optional[Dict[str, Any]] = Field(default_factory=dict)
    prompts: Optional[Dict[str, Any]] = Field(default_factory=dict)
    logging: Optional[Dict[str, Any]] = Field(default_factory=dict)
    sampling: Optional[Dict[str, Any]] = Field(default_factory=dict)
    roots: Optional[Dict[str, Any]] = Field(default_factory=dict)


# =============================================================================
# MCP Content Types
# =============================================================================

class MCPTextContent(BaseModel):
    """Text content in MCP."""
    type: str = "text"
    text: str


class MCPImageContent(BaseModel):
    """Image content in MCP."""
    type: str = "image"
    data: str  # base64 encoded
    mimeType: str


class MCPEmbeddedResource(BaseModel):
    """Embedded resource content."""
    type: str = "resource"
    resource: "MCPResourceContents"


MCPContent = Union[MCPTextContent, MCPImageContent, MCPEmbeddedResource]


# =============================================================================
# MCP Tool Types
# =============================================================================

class MCPToolInputSchema(BaseModel):
    """JSON Schema for tool input."""
    type: str = "object"
    properties: Dict[str, Any] = Field(default_factory=dict)
    required: List[str] = Field(default_factory=list)


class MCPTool(BaseModel):
    """MCP tool definition."""
    name: str
    description: Optional[str] = None
    inputSchema: MCPToolInputSchema = Field(default_factory=MCPToolInputSchema)


class MCPToolCall(BaseModel):
    """Request to call a tool."""
    name: str
    arguments: Optional[Dict[str, Any]] = None


class MCPToolCallResult(BaseModel):
    """Result from a tool call."""
    content: List[MCPContent]
    isError: bool = False
    metadata: Optional[Dict[str, Any]] = None


# =============================================================================
# MCP Resource Types
# =============================================================================

class MCPResource(BaseModel):
    """MCP resource definition."""
    uri: str
    name: str
    description: Optional[str] = None
    mimeType: Optional[str] = None


class MCPResourceTemplate(BaseModel):
    """MCP resource template."""
    uriTemplate: str
    name: str
    description: Optional[str] = None
    mimeType: Optional[str] = None


class MCPResourceContents(BaseModel):
    """Contents of a resource."""
    uri: str
    mimeType: Optional[str] = None
    text: Optional[str] = None
    blob: Optional[str] = None  # base64 encoded


class MCPResourceReadResult(BaseModel):
    """Result from reading a resource."""
    contents: List[MCPResourceContents]


# =============================================================================
# MCP Prompt Types
# =============================================================================

class MCPPromptArgument(BaseModel):
    """Argument for a prompt template."""
    name: str
    description: Optional[str] = None
    required: bool = False


class MCPPrompt(BaseModel):
    """MCP prompt definition."""
    name: str
    description: Optional[str] = None
    arguments: Optional[List[MCPPromptArgument]] = None


class MCPPromptMessage(BaseModel):
    """Message in a prompt result."""
    role: str  # "user" or "assistant"
    content: MCPContent


class MCPPromptResult(BaseModel):
    """Result from getting a prompt."""
    description: Optional[str] = None
    messages: List[MCPPromptMessage]


# =============================================================================
# MCP Sampling Types
# =============================================================================

class MCPModelHint(BaseModel):
    """Hint for model selection."""
    name: Optional[str] = None


class MCPCreateMessageRequest(BaseModel):
    """Request to create a sampling message."""
    messages: List[Dict[str, Any]]
    modelPreferences: Optional[Dict[str, Any]] = None
    systemPrompt: Optional[str] = None
    maxTokens: int = 1024
    temperature: Optional[float] = None
    stopSequences: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class MCPCreateMessageResult(BaseModel):
    """Result from creating a sampling message."""
    model: str
    role: str
    content: MCPContent
    stopReason: Optional[str] = None


# =============================================================================
# MCP Initialize Types
# =============================================================================

class MCPInitializeParams(BaseModel):
    """Parameters for initialize request."""
    protocolVersion: str = MCP_PROTOCOL_VERSION
    capabilities: MCPCapabilities = Field(default_factory=MCPCapabilities)
    clientInfo: Optional[Dict[str, Any]] = None


class MCPInitializeResult(BaseModel):
    """Result from initialize request."""
    protocolVersion: str = MCP_PROTOCOL_VERSION
    capabilities: MCPServerCapabilities
    serverInfo: Dict[str, Any]


# =============================================================================
# JSON-RPC Error Codes
# =============================================================================

class JSONRPCErrorCode(int, Enum):
    """Standard JSON-RPC 2.0 error codes."""
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603


class MCPErrorCode(int, Enum):
    """MCP-specific error codes."""
    RESOURCE_NOT_FOUND = -32001
    RESOURCE_NOT_MODIFIED = -32002
    TOOL_NOT_FOUND = -32003
    INVALID_TOOL_ARGUMENTS = -32004
    PROMPT_NOT_FOUND = -32005
    SAMPLING_REJECTED = -32006
