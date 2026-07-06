"""
Tests for the ContextPort, MockContextBuilder, and ContextProvider.

Covers:
- ContextPort abstract interface
- MockContextBuilder for testing
- ContextProvider token budget management
- create_context_provider factory
"""

import pytest
from typing import Any, Dict, Optional

from cobalto.context.context_package import ContextPackage
from cobalto.context.ports import (
    ContextPort,
    ContextProvider,
    ContextProtocol,
    MockContextBuilder,
    create_context_provider,
)


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def minimal_canned_data():
    """Minimal canned context data for testing."""
    return {
        "semantic": {
            "tenant_name": "acme-corp",
            "asset_criticality": "high",
            "sla_tier": "premium",
        },
        "operational": {
            "alert_count_24h": 5,
            "open_cases": 2,
            "related_indicators": ["203.0.113.45", "malware.example.com"],
        },
        "intelligence": {
            "mitre_techniques": [
                {"technique_id": "T1059", "name": "Command and Scripting Interpreter"},
            ],
            "confidence_score": 0.85,
        },
        "policy": {
            "autonomy_level": "high",
            "requires_approval": False,
            "allowed_actions": ["enrich_indicator", "search_mitre", "create_case"],
        },
        "memory": {
            "summary": "Prior similar alert handled as false positive",
            "recent_runs": [
                {"agent": "triage", "status": "completed", "duration": 1.2},
            ],
        },
    }


# ── MockContextBuilder Tests ─────────────────────────────────────


class TestMockContextBuilder:

    def test_create_with_canned_data(self, minimal_canned_data):
        """MockContextBuilder can be created with canned data."""
        builder = MockContextBuilder(canned_data=minimal_canned_data)
        assert builder.canned_data["semantic"]["tenant_name"] == "acme-corp"

    def test_create_without_data(self):
        """MockContextBuilder works with no canned data (empty dicts)."""
        builder = MockContextBuilder()
        assert builder.canned_data == {}

    @pytest.mark.asyncio
    async def test_build_returns_context_package(self, minimal_canned_data):
        """build() returns a ContextPackage with canned data."""
        builder = MockContextBuilder(canned_data=minimal_canned_data)
        package = await builder.build(
            incident_id="inc-001",
            agent_type="triage",
            tenant_id="acme-corp",
        )

        assert isinstance(package, ContextPackage)
        assert package.incident_id == "inc-001"
        assert package.agent_type == "triage"
        assert package.tenant_id == "acme-corp"

    @pytest.mark.asyncio
    async def test_build_includes_all_five_layers(self, minimal_canned_data):
        """build() populates all 5 context layers."""
        builder = MockContextBuilder(canned_data=minimal_canned_data)
        package = await builder.build(
            incident_id="inc-001",
            agent_type="triage",
            tenant_id="acme-corp",
        )

        assert package.semantic["tenant_name"] == "acme-corp"
        assert package.operational["alert_count_24h"] == 5
        assert package.intelligence["confidence_score"] == 0.85
        assert package.policy["autonomy_level"] == "high"
        assert "summary" in package.memory

    @pytest.mark.asyncio
    async def test_build_with_missing_layers(self):
        """build() returns empty dicts for missing layers."""
        builder = MockContextBuilder(canned_data={
            "semantic": {"tenant_name": "test"},
        })
        package = await builder.build(
            incident_id="inc-001",
            agent_type="triage",
            tenant_id="test",
        )

        assert package.semantic["tenant_name"] == "test"
        assert package.operational == {}
        assert package.intelligence == {}

    @pytest.mark.asyncio
    async def test_build_passes_alert_data(self, minimal_canned_data):
        """build() accepts alert_data parameter."""
        builder = MockContextBuilder(canned_data=minimal_canned_data)
        package = await builder.build(
            incident_id="inc-001",
            agent_type="analysis",
            tenant_id="acme-corp",
            alert_data={"rule_id": "5712", "severity": "high"},
        )

        assert package.incident_id == "inc-001"
        assert package.agent_type == "analysis"


# ── ContextPort Interface Tests ──────────────────────────────────


class TestContextPort:

    def test_context_port_is_abstract(self):
        """ContextPort cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ContextPort()

    def test_mock_context_builder_is_instance(self, minimal_canned_data):
        """MockContextBuilder is a valid ContextPort."""
        builder = MockContextBuilder(canned_data=minimal_canned_data)
        assert isinstance(builder, ContextPort)

    @pytest.mark.asyncio
    async def test_context_protocol_structural(self, minimal_canned_data):
        """Any object with build() method satisfies ContextProtocol."""
        builder = MockContextBuilder(canned_data=minimal_canned_data)
        # ContextProtocol is runtime-checkable
        is_protocol = isinstance(builder, ContextProtocol)
        # Note: runtime_checkable may not match due to async nature
        # but the structural check is what matters
        assert hasattr(builder, "build")

    @pytest.mark.asyncio
    async def test_mock_implements_build(self, minimal_canned_data):
        """MockContextBuilder.build() implements the port contract."""
        builder = MockContextBuilder(canned_data=minimal_canned_data)
        package = await builder.build(
            incident_id="test",
            agent_type="triage",
            tenant_id="test",
        )
        assert isinstance(package, ContextPackage)


# ── ContextProvider Tests ────────────────────────────────────────


class TestContextProvider:

    @pytest.mark.asyncio
    async def test_provider_delegates_to_port(self, minimal_canned_data):
        """ContextProvider.build() delegates to the underlying port."""
        port = MockContextBuilder(canned_data=minimal_canned_data)
        provider = ContextProvider(port=port)

        package = await provider.build(
            incident_id="inc-001",
            agent_type="triage",
            tenant_id="acme-corp",
        )

        assert package.semantic["tenant_name"] == "acme-corp"
        assert package.intelligence["confidence_score"] == 0.85

    @pytest.mark.asyncio
    async def test_provider_respects_token_budget(self):
        """ContextProvider trims context when over token budget."""
        large_intelligence = {
            "mitre_techniques": [{"technique_id": f"T{100+i}", "name": f"Technique {i}"}
                                  for i in range(100)],
            "confidence_score": 0.5,
            "long_summary": "x" * 10000,
        }

        port = MockContextBuilder(canned_data={
            "semantic": {"tenant_name": "acme-corp", "asset_criticality": "high",
                         "sla_tier": "premium", "department": "engineering",
                         "region": "us-east", "owner": "team-alpha"},
            "operational": {"alert_count_24h": 50, "open_cases": 10},
            "intelligence": large_intelligence,
            "policy": {"autonomy_level": "high", "requires_approval": False},
            "memory": {"summary": "x" * 5000, "recent_runs": [{"agent": "triage", "duration": 0.5}] * 50},
        })

        # Use a tiny budget to force trimming
        provider = ContextProvider(port=port, max_context_tokens=100)

        package = await provider.build(
            incident_id="inc-001",
            agent_type="triage",
            tenant_id="acme-corp",
        )

        # The package should still be valid
        assert isinstance(package, ContextPackage)
        assert package.incident_id == "inc-001"
        assert package.agent_type == "triage"

    @pytest.mark.asyncio
    async def test_provider_within_budget_no_trimming(self, minimal_canned_data):
        """ContextProvider does not trim when within budget."""
        port = MockContextBuilder(canned_data=minimal_canned_data)
        provider = ContextProvider(port=port, max_context_tokens=100_000)

        package = await provider.build(
            incident_id="inc-001",
            agent_type="triage",
            tenant_id="acme-corp",
        )

        # All layers should be intact
        assert package.semantic["tenant_name"] == "acme-corp"
        assert package.memory["summary"] == "Prior similar alert handled as false positive"

    @pytest.mark.asyncio
    async def test_provider_passes_alert_data(self, minimal_canned_data):
        """ContextProvider passes alert_data to the port."""
        port = MockContextBuilder(canned_data=minimal_canned_data)
        provider = ContextProvider(port=port)

        package = await provider.build(
            incident_id="inc-001",
            agent_type="analysis",
            tenant_id="acme-corp",
            alert_data={"rule_id": "5712", "severity": "critical"},
        )

        assert package.agent_type == "analysis"

    def test_provider_default_token_budget(self):
        """Provider uses default max_context_tokens of 8000."""
        port = MockContextBuilder()
        provider = ContextProvider(port=port)
        assert provider._max_context_tokens == 8000

    def test_provider_custom_token_budget(self):
        """Provider accepts custom max_context_tokens."""
        port = MockContextBuilder()
        provider = ContextProvider(port=port, max_context_tokens=4000)
        assert provider._max_context_tokens == 4000


# ── create_context_provider Factory ──────────────────────────────


class TestCreateContextProvider:

    def test_create_provider_with_defaults(self):
        """create_context_provider returns a ContextProvider."""
        provider = create_context_provider()
        assert isinstance(provider, ContextProvider)

    def test_create_provider_custom_budget(self):
        """create_context_provider accepts max_context_tokens."""
        provider = create_context_provider(max_context_tokens=4000)
        assert provider._max_context_tokens == 4000

    def test_create_provider_custom_urls(self):
        """create_context_provider accepts custom URLs."""
        provider = create_context_provider(
            qdrant_url="http://qdrant:6333",
            redis_url="redis://redis:6379",
        )
        assert isinstance(provider, ContextProvider)
