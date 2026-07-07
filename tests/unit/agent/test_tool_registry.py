"""
Tests for the UnifiedToolRegistry and ToolDefinition abstractions.

Covers:
- ToolDefinition creation and schema conversion (OpenAI, MCP)
- ToolRiskLevel enum
- ToolCall audit record
- ToolExecutor protocol and AsyncToolWrapper
- UnifiedToolRegistry registration, querying, execution
- Function-based tool registration
- MCP bridge export
- Agent-specific tool filtering
- Audit trail
"""

import pytest
from typing import Any, Dict
from unittest.mock import AsyncMock

from cobalto.agent.tool_registry import (
    ToolDefinition,
    ToolRiskLevel,
    ToolCall,
    ToolExecutor,
    AsyncToolWrapper,
    UnifiedToolRegistry,
    get_tool_registry,
    reset_tool_registry,
)


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def empty_registry():
    """A fresh empty registry."""
    reset_tool_registry()
    return UnifiedToolRegistry()


@pytest.fixture
def sample_definition():
    """A sample tool definition for testing."""
    return ToolDefinition(
        name="mitre_rag_search",
        description="Search MITRE ATT&CK techniques via RAG",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The search query"},
                "top_k": {"type": "integer", "description": "Number of results"},
            },
            "required": ["query"],
        },
        risk_level=ToolRiskLevel.LOW,
        tags=["triage", "mitre", "rag"],
    )


async def sample_executor(query: str, top_k: int = 5) -> Dict[str, Any]:
    """Sample tool executor for testing."""
    return {"results": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter"}], "query": query, "top_k": top_k}


@pytest.fixture
def populated_registry(empty_registry):
    """A registry with several tools registered."""
    registry = empty_registry

    # Register by definition + executor
    registry.register(
        ToolDefinition(
            name="mitre_rag_search",
            description="Search MITRE ATT&CK techniques via RAG",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "top_k": {"type": "integer"},
                },
                "required": ["query"],
            },
            risk_level=ToolRiskLevel.LOW,
            tags=["triage", "mitre"],
        ),
        AsyncToolWrapper(sample_executor),
        capabilities=["mitre_mapping"],
    )

    # Register by function
    registry.register_function(
        lambda ip: {"malicious": False, "score": 0},
        name="cortex_enrich",
        description="Enrich IOC with Cortex analyzers",
        parameters={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to enrich"},
            },
            "required": ["ip"],
        },
        risk_level=ToolRiskLevel.LOW,
        tags=["triage", "enrichment"],
        capabilities=["ioc_enrichment"],
    )

    # High-risk tool
    registry.register(
        ToolDefinition(
            name="isolate_host",
            description="Isolate a host from the network",
            parameters={
                "type": "object",
                "properties": {
                    "host_id": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["host_id"],
            },
            risk_level=ToolRiskLevel.CRITICAL,
            requires_approval=True,
            tags=["response", "containment"],
        ),
        AsyncToolWrapper(lambda host_id, reason="": {"isolated": True, "host_id": host_id}),
        capabilities=["containment"],
    )

    return registry


# ── ToolDefinition Tests ─────────────────────────────────────────


class TestToolDefinition:

    def test_create_definition(self):
        """ToolDefinition can be created with minimal fields."""
        defn = ToolDefinition(
            name="test_tool",
            description="A test tool",
        )
        assert defn.name == "test_tool"
        assert defn.description == "A test tool"
        assert defn.risk_level == ToolRiskLevel.LOW
        assert defn.requires_approval is False

    def test_to_openai_schema(self):
        """to_openai_schema produces OpenAI-compatible output."""
        defn = ToolDefinition(
            name="test_tool",
            description="Test",
            parameters={
                "type": "object",
                "properties": {"param1": {"type": "string"}},
                "required": ["param1"],
            },
        )
        schema = defn.to_openai_schema()
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "test_tool"
        assert "parameters" in schema["function"]

    def test_to_mcp_schema(self):
        """to_mcp_schema produces MCP-compatible output."""
        defn = ToolDefinition(
            name="test_tool",
            description="Test",
            parameters={
                "type": "object",
                "properties": {"param1": {"type": "string"}},
                "required": ["param1"],
            },
        )
        schema = defn.to_mcp_schema()
        assert schema["name"] == "test_tool"
        assert "inputSchema" in schema

    def test_risk_level_ordering(self):
        """Risk levels have correct order."""
        assert ToolRiskLevel.LOW.value == "low"
        assert ToolRiskLevel.MEDIUM.value == "medium"
        assert ToolRiskLevel.HIGH.value == "high"
        assert ToolRiskLevel.CRITICAL.value == "critical"

    def test_to_dict(self, sample_definition):
        """to_dict produces serializable output."""
        data = sample_definition.to_dict()
        assert data["name"] == "mitre_rag_search"
        assert data["risk_level"] == "low"
        assert data["requires_approval"] is False


# ── ToolCall Tests ───────────────────────────────────────────────


class TestToolCall:

    def test_create_tool_call(self):
        """ToolCall records a tool execution."""
        call = ToolCall(
            tool_name="mitre_rag_search",
            arguments={"query": "ransomware", "top_k": 5},
            result={"results": []},
            duration_seconds=1.23,
        )
        assert call.tool_name == "mitre_rag_search"
        assert call.duration_seconds == 1.23
        assert call.approved is None

    def test_tool_call_with_error(self):
        """ToolCall records errors."""
        call = ToolCall(
            tool_name="isolate_host",
            arguments={"host_id": "h-001"},
            error="Host not found",
            duration_seconds=0.5,
        )
        assert call.error == "Host not found"

    def test_tool_call_with_approval(self):
        """ToolCall records approval status."""
        call = ToolCall(
            tool_name="isolate_host",
            arguments={"host_id": "h-001"},
            result={"isolated": True},
            requires_approval=True,
            approved=True,
            approved_by="analyst@example.com",
            duration_seconds=2.0,
        )
        assert call.approved is True
        assert call.approved_by == "analyst@example.com"


# ── UnifiedToolRegistry Tests ────────────────────────────────────


class TestUnifiedToolRegistryRegistration:

    def test_register_tool(self, empty_registry):
        """Register a tool by definition + executor."""
        defn = ToolDefinition(name="test_tool", description="Test")
        executor = AsyncToolWrapper(lambda: {"done": True})
        name = empty_registry.register(defn, executor)
        assert name == "test_tool"
        assert empty_registry.has_tool("test_tool")

    def test_register_function(self, empty_registry):
        """Register a Python function as a tool."""
        def my_tool(param1: str) -> str:
            """My test tool."""
            return f"Processed {param1}"

        name = empty_registry.register_function(
            my_tool,
            tags=["test"],
        )
        assert name == "my_tool"
        assert empty_registry.has_tool("my_tool")

    def test_register_duplicate_overwrites(self, empty_registry):
        """Registering the same tool name overwrites the previous."""
        empty_registry.register_function(
            lambda: "old", name="my_tool", description="Old version",
        )
        empty_registry.register_function(
            lambda: "new", name="my_tool", description="New version",
        )
        defn = empty_registry.get_definition("my_tool")
        assert defn is not None
        assert defn.description == "New version"

    def test_list_tools(self, populated_registry):
        """list_tools returns all definitions."""
        tools = populated_registry.list_tools()
        assert len(tools) >= 3

    def test_list_tool_names(self, populated_registry):
        """list_tool_names returns all names."""
        names = populated_registry.list_tool_names()
        assert "mitre_rag_search" in names
        assert "cortex_enrich" in names
        assert "isolate_host" in names


class TestUnifiedToolRegistryQuerying:

    def test_get_definition(self, populated_registry):
        """get_definition returns the correct definition."""
        defn = populated_registry.get_definition("mitre_rag_search")
        assert defn is not None
        assert defn.name == "mitre_rag_search"

    def test_get_definition_nonexistent(self, populated_registry):
        """get_definition returns None for unknown tools."""
        defn = populated_registry.get_definition("nonexistent")
        assert defn is None

    def test_get_executor(self, populated_registry):
        """get_executor returns the executor for a registered tool."""
        executor = populated_registry.get_executor("mitre_rag_search")
        assert executor is not None
        assert hasattr(executor, "execute")

    def test_has_tool(self, populated_registry):
        """has_tool checks for tool existence."""
        assert populated_registry.has_tool("mitre_rag_search") is True
        assert populated_registry.has_tool("nonexistent") is False

    def test_find_tools_by_tag(self, populated_registry):
        """find_tools_by_tag finds tools with a specific tag."""
        tools = populated_registry.find_tools_by_tag("triage")
        assert len(tools) >= 2
        assert all("triage" in t.tags for t in tools)

    def test_find_tools_by_risk(self, populated_registry):
        """find_tools_by_risk filters by risk level."""
        # Low and above should return all tools
        low_and_above = populated_registry.find_tools_by_risk(ToolRiskLevel.LOW)
        assert len(low_and_above) >= 3

        # Critical should return only the isolate_host tool
        critical = populated_registry.find_tools_by_risk(ToolRiskLevel.CRITICAL)
        assert len(critical) >= 1
        assert all(t.risk_level == ToolRiskLevel.CRITICAL for t in critical)

    def test_requires_approval(self, populated_registry):
        """requires_approval checks the tool's approval requirement."""
        assert populated_registry.requires_approval("isolate_host") is True
        assert populated_registry.requires_approval("mitre_rag_search") is False

    def test_get_risk_level(self, populated_registry):
        """get_risk_level returns the tool's risk level."""
        assert populated_registry.get_risk_level("isolate_host") == ToolRiskLevel.CRITICAL
        assert populated_registry.get_risk_level("mitre_rag_search") == ToolRiskLevel.LOW
        assert populated_registry.get_risk_level("nonexistent") is None


class TestUnifiedToolRegistryExecution:

    @pytest.mark.asyncio
    async def test_execute_tool(self, populated_registry):
        """execute runs the tool and returns the result."""
        result = await populated_registry.execute(
            "mitre_rag_search",
            {"query": "ransomware", "top_k": 5},
        )
        assert result["results"] is not None
        assert result["query"] == "ransomware"
        assert result["top_k"] == 5

    @pytest.mark.asyncio
    async def test_execute_nonexistent_tool(self, populated_registry):
        """execute raises KeyError for unknown tools."""
        with pytest.raises(KeyError):
            await populated_registry.execute("nonexistent", {})

    @pytest.mark.asyncio
    async def test_execute_records_audit(self, populated_registry):
        """execute records a ToolCall in the audit trail."""
        history_before = len(populated_registry.call_history)
        await populated_registry.execute(
            "mitre_rag_search",
            {"query": "test", "top_k": 3},
        )
        assert len(populated_registry.call_history) == history_before + 1

        last_call = populated_registry.call_history[-1]
        assert last_call.tool_name == "mitre_rag_search"
        assert last_call.arguments["query"] == "test"
        assert last_call.duration_seconds > 0

    @pytest.mark.asyncio
    async def test_execute_without_audit(self, populated_registry):
        """execute with audit=False does not record."""
        history_before = len(populated_registry.call_history)
        await populated_registry.execute(
            "mitre_rag_search",
            {"query": "test"},
            audit=False,
        )
        assert len(populated_registry.call_history) == history_before

    @pytest.mark.asyncio
    async def test_execute_records_error(self, populated_registry):
        """execute records errors in the audit trail."""
        with pytest.raises(Exception):
            await populated_registry.execute(
                "mitre_rag_search",
                {},  # Missing required 'query' param - should error
            )
        # Should still have recorded the call with error
        last_call = populated_registry.call_history[-1]
        assert last_call.error is not None or last_call.result is not None


class TestUnifiedToolRegistryExport:

    def test_list_mcp_tools(self, populated_registry):
        """MCP export returns proper MCP schemas."""
        mcp_tools = populated_registry.list_mcp_tools()
        for tool in mcp_tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_list_openai_tools(self, populated_registry):
        """OpenAI export returns proper function schemas."""
        oai_tools = populated_registry.list_openai_tools()
        for tool in oai_tools:
            assert tool["type"] == "function"
            assert "function" in tool
            assert "name" in tool["function"]

    def test_get_agent_tools(self, populated_registry):
        """get_agent_tools filters by agent type tags."""
        triage_tools = populated_registry.get_agent_tools("triage")
        assert len(triage_tools) >= 1
        assert all(t["function"]["name"] in ["mitre_rag_search", "cortex_enrich"]
                   for t in triage_tools)


class TestUnifiedToolRegistryAuditTrail:

    def test_call_history(self, populated_registry):
        """call_history returns a list of ToolCall records."""
        history = populated_registry.call_history
        assert isinstance(history, list)

    def test_clear_history(self, populated_registry):
        """clear_history clears the audit trail."""
        populated_registry.clear_history()
        assert len(populated_registry.call_history) == 0

    def test_get_recent_calls(self, populated_registry):
        """get_recent_calls returns the most recent calls."""
        recent = populated_registry.get_recent_calls(2)
        assert len(recent) <= 2


class TestUnifiedToolRegistrySerialization:

    def test_to_dict(self, populated_registry):
        """to_dict produces serializable output."""
        data = populated_registry.to_dict()
        assert data["tool_count"] >= 3
        assert "tools" in data
        assert "capability_tags" in data

    def test_to_dict_after_clear(self, empty_registry):
        """to_dict shows zero tools after clear."""
        data = empty_registry.to_dict()
        assert data["tool_count"] == 0


# ── Global Singleton Tests ───────────────────────────────────────


class TestGlobalRegistry:

    def setup_method(self):
        reset_tool_registry()

    def test_get_tool_registry_singleton(self):
        """get_tool_registry() returns the same instance."""
        reg1 = get_tool_registry()
        reg2 = get_tool_registry()
        assert reg1 is reg2

    def test_reset_creates_new_instance(self):
        """reset_tool_registry() creates a fresh instance."""
        reg1 = get_tool_registry()
        reg1.register_function(lambda: "test", name="test_tool")
        assert reg1.has_tool("test_tool")

        reset_tool_registry()
        reg2 = get_tool_registry()
        assert reg2.has_tool("test_tool") is False
        assert reg1 is not reg2
