"""Tests for MCP protocol types."""

import pytest
from cobalto.mcp.protocol import (
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCError,
    JSONRPCNotification,
    MCPTool,
    MCPResource,
    MCPPrompt,
    MCPTextContent,
    MCPToolCallResult,
    MCPInitializeParams,
    MCPInitializeResult,
    MCPCapabilities,
    MCPServerCapabilities,
    MCP_PROTOCOL_VERSION,
    JSONRPCErrorCode,
    MCPErrorCode,
)


class TestJSONRPC:
    """Test JSON-RPC message types."""

    def test_request_creation(self):
        """Test creating a JSON-RPC request."""
        request = JSONRPCRequest(
            method="tools/list",
            params={"limit": 10},
        )
        assert request.jsonrpc == "2.0"
        assert request.method == "tools/list"
        assert request.params == {"limit": 10}
        assert request.id is not None

    def test_request_without_params(self):
        """Test creating request without params."""
        request = JSONRPCRequest(method="ping")
        assert request.params is None

    def test_response_success(self):
        """Test creating a success response."""
        response = JSONRPCResponse(
            id="test-123",
            result={"tools": []},
        )
        assert response.id == "test-123"
        assert response.result == {"tools": []}
        assert response.error is None

    def test_response_error(self):
        """Test creating an error response."""
        error = JSONRPCError(
            code=-32601,
            message="Method not found",
        )
        response = JSONRPCResponse(
            id="test-123",
            error=error,
        )
        assert response.error.code == -32601
        assert response.error.message == "Method not found"

    def test_notification(self):
        """Test creating a notification (no id)."""
        notification = JSONRPCNotification(
            method="notifications/initialized",
            params={"status": "ready"},
        )
        assert notification.method == "notifications/initialized"


class TestMCPTypes:
    """Test MCP-specific types."""

    def test_tool_creation(self):
        """Test creating an MCP tool."""
        tool = MCPTool(
            name="block_ip",
            description="Block an IP address",
            inputSchema={
                "type": "object",
                "properties": {"ip": {"type": "string"}},
            },
        )
        assert tool.name == "block_ip"
        assert tool.description == "Block an IP address"

    def test_resource_creation(self):
        """Test creating an MCP resource."""
        resource = MCPResource(
            uri="opencti://indicators/123",
            name="Indicator 123",
            description="A threat indicator",
            mimeType="application/json",
        )
        assert resource.uri == "opencti://indicators/123"
        assert resource.name == "Indicator 123"

    def test_prompt_creation(self):
        """Test creating an MCP prompt."""
        prompt = MCPPrompt(
            name="triage",
            description="Triage workflow prompt",
        )
        assert prompt.name == "triage"

    def test_text_content(self):
        """Test creating text content."""
        content = MCPTextContent(text="Hello, world!")
        assert content.type == "text"
        assert content.text == "Hello, world!"

    def test_tool_call_result(self):
        """Test creating a tool call result."""
        result = MCPToolCallResult(
            content=[MCPTextContent(text="Success")],
            isError=False,
        )
        assert len(result.content) == 1
        assert result.isError is False

    def test_initialize_params(self):
        """Test creating initialize params."""
        params = MCPInitializeParams(
            protocolVersion=MCP_PROTOCOL_VERSION,
            capabilities=MCPCapabilities(tools={}),
        )
        assert params.protocolVersion == MCP_PROTOCOL_VERSION

    def test_initialize_result(self):
        """Test creating initialize result."""
        result = MCPInitializeResult(
            protocolVersion=MCP_PROTOCOL_VERSION,
            capabilities=MCPServerCapabilities(tools={}),
            serverInfo={"name": "test-server", "version": "1.0.0"},
        )
        assert result.serverInfo["name"] == "test-server"


class TestErrorCodes:
    """Test error code enums."""

    def test_jsonrpc_error_codes(self):
        """Test JSON-RPC error codes."""
        assert JSONRPCErrorCode.PARSE_ERROR == -32700
        assert JSONRPCErrorCode.METHOD_NOT_FOUND == -32601

    def test_mcp_error_codes(self):
        """Test MCP error codes."""
        assert MCPErrorCode.RESOURCE_NOT_FOUND == -32001
        assert MCPErrorCode.TOOL_NOT_FOUND == -32003
