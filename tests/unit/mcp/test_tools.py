"""Tests for MCP Tool Registry."""

import pytest
from cobalto.mcp.registry.tools import ToolRegistry, mcp_tool, get_tool_registry
from cobalto.mcp.protocol import MCPToolCallResult, MCPTextContent


class TestToolRegistry:
    """Test ToolRegistry class."""

    def test_register_tool(self):
        """Test registering a tool."""
        registry = ToolRegistry()

        @registry.register(
            name="test_tool",
            description="A test tool",
        )
        def test_func(x: int) -> int:
            return x * 2

        assert registry.has_tool("test_tool")
        assert "test_tool" in registry.list_tool_names()

    def test_list_tools(self):
        """Test listing tools."""
        registry = ToolRegistry()

        @registry.register(name="tool1", description="Tool 1")
        def func1() -> None:
            pass

        @registry.register(name="tool2", description="Tool 2")
        def func2() -> None:
            pass

        tools = registry.list_tools()
        assert len(tools) == 2
        names = [t.name for t in tools]
        assert "tool1" in names
        assert "tool2" in names

    def test_get_mcp_tool(self):
        """Test getting MCP tool representation."""
        registry = ToolRegistry()

        @registry.register(
            name="block_ip",
            description="Block an IP address",
            input_schema={
                "type": "object",
                "properties": {"ip": {"type": "string"}},
            },
        )
        def block_ip_func(ip: str) -> str:
            return f"Blocked {ip}"

        tool = registry.get_mcp_tool("block_ip")
        assert tool is not None
        assert tool.name == "block_ip"
        assert "ip" in tool.inputSchema.properties

    @pytest.mark.asyncio
    async def test_call_tool_sync(self):
        """Test calling a synchronous tool."""
        registry = ToolRegistry()

        @registry.register(name="add")
        def add(x: int, y: int) -> int:
            return x + y

        result = await registry.call_tool("add", {"x": 5, "y": 3})
        assert isinstance(result, MCPToolCallResult)
        assert not result.isError
        assert len(result.content) == 1

    @pytest.mark.asyncio
    async def test_call_tool_async(self):
        """Test calling an async tool."""
        registry = ToolRegistry()

        @registry.register(name="async_add")
        async def async_add(x: int, y: int) -> int:
            return x + y

        result = await registry.call_tool("async_add", {"x": 10, "y": 20})
        assert isinstance(result, MCPToolCallResult)
        assert not result.isError

    @pytest.mark.asyncio
    async def test_call_tool_not_found(self):
        """Test calling a non-existent tool."""
        registry = ToolRegistry()
        result = await registry.call_tool("nonexistent")
        assert result.isError is True
        assert "not found" in result.content[0].text.lower()

    @pytest.mark.asyncio
    async def test_call_tool_with_error(self):
        """Test calling a tool that raises an error."""
        registry = ToolRegistry()

        @registry.register(name="error_tool")
        def error_func() -> str:
            raise ValueError("Test error")

        result = await registry.call_tool("error_tool")
        assert result.isError is True
        assert "error" in result.content[0].text.lower()

    def test_get_tools_by_tag(self):
        """Test getting tools by tag."""
        registry = ToolRegistry()

        @registry.register(name="wazuh_tool", tags=["wazuh", "siem"])
        def wazuh_func() -> None:
            pass

        @registry.register(name="opencti_tool", tags=["opencti", "threat-intel"])
        def opencti_func() -> None:
            pass

        wazuh_tools = registry.get_tools_by_tag("wazuh")
        assert len(wazuh_tools) == 1
        assert wazuh_tools[0].name == "wazuh_tool"

    def test_unregister_tool(self):
        """Test unregistering a tool."""
        registry = ToolRegistry()

        @registry.register(name="temp_tool")
        def temp_func() -> None:
            pass

        assert registry.has_tool("temp_tool")
        assert registry.unregister("temp_tool")
        assert not registry.has_tool("temp_tool")

    def test_clear(self):
        """Test clearing all tools."""
        registry = ToolRegistry()

        @registry.register(name="tool1")
        def func1() -> None:
            pass

        @registry.register(name="tool2")
        def func2() -> None:
            pass

        registry.clear()
        assert len(registry.list_tool_names()) == 0


class TestGlobalRegistry:
    """Test global tool registry."""

    def test_global_registry_singleton(self):
        """Test that global registry is a singleton."""
        reg1 = get_tool_registry()
        reg2 = get_tool_registry()
        assert reg1 is reg2

    def test_mcp_tool_decorator(self):
        """Test mcp_tool decorator on global registry."""
        @mcp_tool(name="global_test_tool", description="Global test")
        def global_func() -> str:
            return "global"

        registry = get_tool_registry()
        assert registry.has_tool("global_test_tool")
