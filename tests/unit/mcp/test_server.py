"""Tests for MCP Server."""

import pytest
import json
from cobalto.mcp.server import MCPServer
from cobalto.mcp.registry.tools import ToolRegistry
from cobalto.mcp.registry.resources import ResourceRegistry
from cobalto.mcp.registry.prompts import PromptRegistry
from cobalto.mcp.protocol import MCP_PROTOCOL_VERSION


class TestMCPServer:
    """Test MCPServer class."""

    @pytest.fixture
    def registries(self):
        """Create fresh registries."""
        return {
            "tools": ToolRegistry(),
            "resources": ResourceRegistry(),
            "prompts": PromptRegistry(),
        }

    @pytest.fixture
    def server(self, registries):
        """Create MCP server with fresh registries."""
        return MCPServer(
            name="test-server",
            version="1.0.0",
            tool_registry=registries["tools"],
            resource_registry=registries["resources"],
            prompt_registry=registries["prompts"],
        )

    @pytest.mark.asyncio
    async def test_initialize(self, server):
        """Test initialize request."""
        request = {
            "jsonrpc": "2.0",
            "id": "test-1",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert data["id"] == "test-1"
        assert "result" in data
        assert data["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
        assert data["result"]["serverInfo"]["name"] == "test-server"

    @pytest.mark.asyncio
    async def test_ping(self, server):
        """Test ping request."""
        request = {
            "jsonrpc": "2.0",
            "id": "test-2",
            "method": "ping",
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert data["id"] == "test-2"
        assert data["result"] == {}

    @pytest.mark.asyncio
    async def test_tools_list_empty(self, server):
        """Test tools/list with no tools registered."""
        request = {
            "jsonrpc": "2.0",
            "id": "test-3",
            "method": "tools/list",
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert data["result"]["tools"] == []

    @pytest.mark.asyncio
    async def test_tools_list_with_tools(self, server, registries):
        """Test tools/list with registered tools."""
        @registries["tools"].register(
            name="test_tool",
            description="A test tool",
        )
        def test_func() -> str:
            return "test"

        request = {
            "jsonrpc": "2.0",
            "id": "test-4",
            "method": "tools/list",
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert len(data["result"]["tools"]) == 1
        assert data["result"]["tools"][0]["name"] == "test_tool"

    @pytest.mark.asyncio
    async def test_tools_call(self, server, registries):
        """Test tools/call request."""
        @registries["tools"].register(
            name="add",
            description="Add two numbers",
        )
        def add(x: int, y: int) -> int:
            return x + y

        request = {
            "jsonrpc": "2.0",
            "id": "test-5",
            "method": "tools/call",
            "params": {
                "name": "add",
                "arguments": {"x": 5, "y": 3},
            },
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert "result" in data
        assert data["result"]["isError"] is False

    @pytest.mark.asyncio
    async def test_tools_call_not_found(self, server):
        """Test tools/call with non-existent tool."""
        request = {
            "jsonrpc": "2.0",
            "id": "test-6",
            "method": "tools/call",
            "params": {
                "name": "nonexistent",
                "arguments": {},
            },
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert data["result"]["isError"] is True

    @pytest.mark.asyncio
    async def test_resources_list(self, server, registries):
        """Test resources/list request."""
        @registries["resources"].register(
            uri="test://resource",
            name="Test Resource",
        )
        def test_resource() -> str:
            return "test"

        request = {
            "jsonrpc": "2.0",
            "id": "test-7",
            "method": "resources/list",
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert len(data["result"]["resources"]) == 1

    @pytest.mark.asyncio
    async def test_resources_read(self, server, registries):
        """Test resources/read request."""
        @registries["resources"].register(
            uri="test://resource/123",
            name="Test Resource",
        )
        def test_resource(uri: str) -> dict:
            return {"id": "123", "data": "test"}

        request = {
            "jsonrpc": "2.0",
            "id": "test-8",
            "method": "resources/read",
            "params": {"uri": "test://resource/123"},
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert "contents" in data["result"]

    @pytest.mark.asyncio
    async def test_prompts_list(self, server, registries):
        """Test prompts/list request."""
        @registries["prompts"].register(
            name="test_prompt",
            description="A test prompt",
        )
        def test_prompt() -> str:
            return "test prompt"

        request = {
            "jsonrpc": "2.0",
            "id": "test-9",
            "method": "prompts/list",
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert len(data["result"]["prompts"]) == 1

    @pytest.mark.asyncio
    async def test_prompts_get(self, server, registries):
        """Test prompts/get request."""
        @registries["prompts"].register(
            name="greet",
            description="Greeting prompt",
            arguments=[{"name": "name", "description": "Name to greet", "required": True}],
        )
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        request = {
            "jsonrpc": "2.0",
            "id": "test-10",
            "method": "prompts/get",
            "params": {"name": "greet", "arguments": {"name": "World"}},
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert "messages" in data["result"]

    @pytest.mark.asyncio
    async def test_method_not_found(self, server):
        """Test method not found error."""
        request = {
            "jsonrpc": "2.0",
            "id": "test-11",
            "method": "nonexistent/method",
        }

        response = await server.handle_message(request)
        data = json.loads(response)

        assert "error" in data
        assert data["error"]["code"] == -32601

    @pytest.mark.asyncio
    async def test_parse_error(self, server):
        """Test JSON parse error."""
        response = await server.handle_message("invalid json")
        data = json.loads(response)

        assert "error" in data
        assert data["error"]["code"] == -32700

    def test_server_info(self, server):
        """Test getting server info."""
        info = server.get_server_info()
        assert info["name"] == "test-server"
        assert info["version"] == "1.0.0"
        assert "capabilities" in info
