"""
MCP Server - Core server implementation handling JSON-RPC protocol.
"""

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Union

from cobalto.mcp.protocol import (
    JSONRPCMessage,
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCError,
    JSONRPCNotification,
    MCPMethod,
    MCPServerCapabilities,
    MCPInitializeParams,
    MCPInitializeResult,
    MCPToolCall,
    MCPToolCallResult,
    MCPResourceReadResult,
    MCPPromptResult,
    MCPTextContent,
    MCPCreateMessageRequest,
    MCPCreateMessageResult,
    MCP_PROTOCOL_VERSION,
    JSONRPCErrorCode,
    MCPErrorCode,
)
from cobalto.mcp.registry.tools import ToolRegistry, get_tool_registry
from cobalto.mcp.registry.resources import ResourceRegistry, get_resource_registry
from cobalto.mcp.registry.prompts import PromptRegistry, get_prompt_registry

logger = logging.getLogger(__name__)


class MCPServer:
    """
    MCP Server implementation handling JSON-RPC 2.0 protocol.

    Supports:
    - Tool listing and calling
    - Resource listing and reading
    - Prompt listing and getting
    - Sampling (delegated to host)
    - Capability negotiation
    """

    def __init__(
        self,
        name: str = "cobalto-mcp-server",
        version: str = "0.1.0",
        tool_registry: Optional[ToolRegistry] = None,
        resource_registry: Optional[ResourceRegistry] = None,
        prompt_registry: Optional[PromptRegistry] = None,
    ):
        self.name = name
        self.version = version
        self.tool_registry = tool_registry or get_tool_registry()
        self.resource_registry = resource_registry or get_resource_registry()
        self.prompt_registry = prompt_registry or get_prompt_registry()

        # State
        self._initialized = False
        self._client_info: Optional[Dict[str, Any]] = None
        self._client_capabilities: Optional[Dict[str, Any]] = None

        # Custom handlers
        self._sampling_handler: Optional[Callable] = None
        self._notification_handlers: Dict[str, Callable] = {}

        # Method routing
        self._method_handlers: Dict[str, Callable] = {
            MCPMethod.INITIALIZE: self._handle_initialize,
            MCPMethod.PING: self._handle_ping,
            MCPMethod.TOOLS_LIST: self._handle_tools_list,
            MCPMethod.TOOLS_CALL: self._handle_tools_call,
            MCPMethod.RESOURCES_LIST: self._handle_resources_list,
            MCPMethod.RESOURCES_READ: self._handle_resources_read,
            MCPMethod.RESOURCES_TEMPLATES_LIST: self._handle_resources_templates_list,
            MCPMethod.PROMPTS_LIST: self._handle_prompts_list,
            MCPMethod.PROMPTS_GET: self._handle_prompts_get,
            MCPMethod.SAMPLING_CREATE_MESSAGE: self._handle_sampling,
            MCPMethod.LOGGING_SET_LEVEL: self._handle_logging_set_level,
        }

    def set_sampling_handler(self, handler: Callable) -> None:
        """Set custom sampling handler for LLM callbacks."""
        self._sampling_handler = handler

    def on_notification(self, method: str, handler: Callable) -> None:
        """Register a notification handler."""
        self._notification_handlers[method] = handler

    @property
    def capabilities(self) -> MCPServerCapabilities:
        """Get server capabilities."""
        caps = MCPServerCapabilities()

        if self.tool_registry.list_tool_names():
            caps.tools = {}

        if self.resource_registry.list_uris():
            caps.resources = {"listChanged": True}

        if self.prompt_registry.list_prompt_names():
            caps.prompts = {"listChanged": True}

        if self._sampling_handler:
            caps.sampling = {}

        caps.logging = {}

        return caps

    async def handle_message(self, message: Union[str, Dict[str, Any]]) -> Optional[str]:
        """
        Handle an incoming JSON-RPC message.

        Returns:
            JSON-RPC response as string, or None for notifications
        """
        try:
            # Parse message
            if isinstance(message, str):
                data = json.loads(message)
            else:
                data = message

            # Check if it's a notification (no id)
            if "id" not in data:
                notification = JSONRPCNotification(**data)
                await self._handle_notification(notification)
                return None

            # It's a request
            request = JSONRPCRequest(**data)

            # Route to handler
            handler = self._method_handlers.get(request.method)
            if not handler:
                return self._create_error_response(
                    request.id,
                    JSONRPCErrorCode.METHOD_NOT_FOUND,
                    f"Method not found: {request.method}",
                )

            # Execute handler
            result = await handler(request)

            # Create response
            return self._create_success_response(request.id, result)

        except json.JSONDecodeError as e:
            return self._create_error_response(
                None,
                JSONRPCErrorCode.PARSE_ERROR,
                f"Parse error: {str(e)}",
            )
        except Exception as e:
            logger.exception(f"Error handling message: {e}")
            return self._create_error_response(
                None,
                JSONRPCErrorCode.INTERNAL_ERROR,
                f"Internal error: {str(e)}",
            )

    async def _handle_initialize(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle initialize request."""
        params = MCPInitializeParams(**(request.params or {}))

        self._client_capabilities = params.capabilities.model_dump()
        self._client_info = params.clientInfo

        result = MCPInitializeResult(
            protocolVersion=MCP_PROTOCOL_VERSION,
            capabilities=self.capabilities,
            serverInfo={
                "name": self.name,
                "version": self.version,
            },
        )

        self._initialized = True
        logger.info(f"MCP Server initialized: {self.name} v{self.version}")

        return result.model_dump()

    async def _handle_ping(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle ping request."""
        return {}

    async def _handle_tools_list(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle tools/list request."""
        tools = self.tool_registry.list_tools()
        return {"tools": [tool.model_dump() for tool in tools]}

    async def _handle_tools_call(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle tools/call request."""
        params = request.params or {}
        tool_call = MCPToolCall(**params)

        result = await self.tool_registry.call_tool(
            name=tool_call.name,
            arguments=tool_call.arguments,
        )

        return result.model_dump()

    async def _handle_resources_list(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle resources/list request."""
        resources = self.resource_registry.list_resources()
        return {"resources": [r.model_dump() for r in resources]}

    async def _handle_resources_read(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle resources/read request."""
        params = request.params or {}
        uri = params.get("uri", "")

        result = await self.resource_registry.read_resource(uri)
        return result.model_dump()

    async def _handle_resources_templates_list(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle resources/templates/list request."""
        templates = self.resource_registry.list_templates()
        return {"resourceTemplates": [t.model_dump() for t in templates]}

    async def _handle_prompts_list(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle prompts/list request."""
        prompts = self.prompt_registry.list_prompts()
        return {"prompts": [p.model_dump() for p in prompts]}

    async def _handle_prompts_get(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle prompts/get request."""
        params = request.params or {}
        name = params.get("name", "")
        arguments = params.get("arguments")

        result = await self.prompt_registry.get_prompt(name=name, arguments=arguments)
        return result.model_dump()

    async def _handle_sampling(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle sampling/createMessage request."""
        if not self._sampling_handler:
            return self._create_error_response(
                request.id,
                MCPErrorCode.SAMPLING_REJECTED,
                "Sampling not supported by this server",
            )

        params = MCPCreateMessageRequest(**(request.params or {}))
        result = await self._sampling_handler(params)
        return result.model_dump()

    async def _handle_logging_set_level(self, request: JSONRPCRequest) -> Dict[str, Any]:
        """Handle logging/setLevel request."""
        params = request.params or {}
        level = params.get("level", "info")
        logger.info(f"Log level set to: {level}")
        return {}

    async def _handle_notification(self, notification: JSONRPCNotification) -> None:
        """Handle incoming notification."""
        handler = self._notification_handlers.get(notification.method)
        if handler:
            await handler(notification.params)
        else:
            logger.debug(f"Unhandled notification: {notification.method}")

    def _create_success_response(self, request_id: Union[str, int], result: Any) -> str:
        """Create a success JSON-RPC response."""
        response = JSONRPCResponse(
            id=request_id,
            result=result,
        )
        return json.dumps(response.model_dump(), default=str)

    def _create_error_response(
        self,
        request_id: Optional[Union[str, int]],
        code: Union[JSONRPCErrorCode, MCPErrorCode, int],
        message: str,
        data: Optional[Any] = None,
    ) -> str:
        """Create an error JSON-RPC response."""
        response = JSONRPCResponse(
            id=request_id or "",
            error=JSONRPCError(
                code=int(code),
                message=message,
                data=data,
            ),
        )
        return json.dumps(response.model_dump(), default=str)

    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        return {
            "name": self.name,
            "version": self.version,
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": self.capabilities.model_dump(),
        }
