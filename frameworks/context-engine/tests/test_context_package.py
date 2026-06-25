"""Tests for context package."""

import pytest
from cobalto.context.context_package import ContextBuilder, ContextPackage
from cobalto.context.semantic import SemanticLayer
from cobalto.context.operational import OperationalLayer
from cobalto.context.intelligence import IntelligenceLayer
from cobalto.context.policy import PolicyLayer
from cobalto.context.memory import MemoryLayer


class TestContextPackage:
    """Tests for ContextPackage model."""

    def test_context_package_creation(self):
        package = ContextPackage(
            incident_id="test-123",
            agent_type="triage",
            tenant_id="tenant-1",
        )
        assert package.incident_id == "test-123"
        assert package.agent_type == "triage"
        assert package.tenant_id == "tenant-1"
        assert package.assembled_at is not None

    def test_to_prompt_context(self):
        package = ContextPackage(
            incident_id="test-123",
            agent_type="triage",
            tenant_id="tenant-1",
            semantic={"tenant_name": "Acme Corp", "sla_tier": "premium"},
            operational={"alert_count_24h": 5},
            intelligence={"confidence_score": 0.85},
            policy={"autonomy_level": "high"},
        )
        prompt = package.to_prompt_context()
        assert "Acme Corp" in prompt
        assert "premium" in prompt
        assert "5" in prompt
        assert "0.85" in prompt
        assert "high" in prompt


class TestSemanticLayer:
    """Tests for SemanticLayer."""

    @pytest.mark.asyncio
    async def test_load_basic(self):
        layer = SemanticLayer()
        result = await layer.load("tenant-1")
        assert "tenant_id" in result
        assert "sla_tier" in result
        assert "asset_criticality" in result
        assert "business_hours" in result

    def test_asset_criticality_critical(self):
        layer = SemanticLayer()
        alert_data = {"host_name": "dc01.corp.local"}
        result = layer._get_asset_criticality(alert_data)
        assert result == "critical"

    def test_asset_criticality_high(self):
        layer = SemanticLayer()
        alert_data = {"host_name": "web01.corp.local"}
        result = layer._get_asset_criticality(alert_data)
        assert result == "high"

    def test_asset_criticality_medium(self):
        layer = SemanticLayer()
        alert_data = {"host_name": "workstation01.corp.local"}
        result = layer._get_asset_criticality(alert_data)
        assert result == "medium"

    def test_asset_criticality_unknown(self):
        layer = SemanticLayer()
        result = layer._get_asset_criticality(None)
        assert result == "unknown"


class TestPolicyLayer:
    """Tests for PolicyLayer."""

    @pytest.mark.asyncio
    async def test_load_triage(self):
        layer = PolicyLayer()
        result = await layer.load("tenant-1", "triage")
        assert result["autonomy_level"] == "high"
        assert result["requires_approval"] is False
        assert "enrich_indicator" in result["allowed_actions"]

    @pytest.mark.asyncio
    async def test_load_response(self):
        layer = PolicyLayer()
        result = await layer.load("tenant-1", "response")
        assert result["requires_approval"] is True
        assert "isolate_host" in result["allowed_actions"]

    def test_requires_approval(self):
        layer = PolicyLayer()
        assert layer.requires_approval("isolate_host") is True
        assert layer.requires_approval("block_ip") is True
        assert layer.requires_approval("enrich_indicator") is False


class TestMemoryLayer:
    """Tests for MemoryLayer."""

    def test_summarize_runs(self):
        layer = MemoryLayer("redis://localhost:6379")
        runs = [
            {"agent_type": "triage", "status": "completed"},
            {"agent_type": "triage", "status": "completed"},
            {"agent_type": "analysis", "status": "failed"},
        ]
        summary = layer._summarize_runs(runs)
        assert "3" in summary
        assert "triage" in summary
        assert "analysis" in summary
