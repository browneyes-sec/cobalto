"""Tests for Silver Response Agent."""

import pytest
from cobalto.agent.base_agent import AgentConfig, AgentType
from services.langgraph.agents.response import SilverResponseAgent


class TestSilverResponseAgent:
    """Tests for SilverResponseAgent."""

    def test_agent_initialization(self):
        agent = SilverResponseAgent()
        assert agent.config.name == "Silver Response Agent"
        assert agent.config.agent_type == AgentType.RESPONSE
        assert agent.config.model == "gpt-4o"
        assert agent.config.temperature == 0.0
        assert agent.config.requires_approval is True

    def test_agent_has_tools(self):
        agent = SilverResponseAgent()
        tools = agent.get_tools()
        assert len(tools) == 4
        tool_names = [t.name for t in tools]
        assert "n8n_execute" in tool_names
        assert "wazuh_active_response" in tool_names
        assert "firewall_block" in tool_names
        assert "slack_notify" in tool_names

    def test_system_prompt(self):
        agent = SilverResponseAgent()
        prompt = agent.get_system_prompt()
        assert "Response Agent" in prompt
        assert "Cobalto" in prompt

    def test_requires_approval(self):
        agent = SilverResponseAgent()
        policy = {"high_risk_actions": ["isolate_host", "block_ip"]}
        assert agent._requires_approval("isolate_host", policy) is True
        assert agent._requires_approval("block_ip", policy) is True
        assert agent._requires_approval("enrich_indicator", policy) is False

    def test_calculate_priority(self):
        agent = SilverResponseAgent()
        rec = {"requires_approval": True}
        risk_score = 80
        priority = agent._calculate_priority(rec, risk_score)
        assert priority >= 15  # 10 (approval) + 5 (high risk)

    def test_estimate_impact(self):
        agent = SilverResponseAgent()
        assert agent._estimate_impact({"action": "isolate_host"}) == "high"
        assert agent._estimate_impact({"action": "block_ip"}) == "high"
        assert agent._estimate_impact({"action": "disable_user"}) == "medium"
        assert agent._estimate_impact({"action": "enrich_indicator"}) == "low"

    def test_generate_rollback_plan(self):
        agent = SilverResponseAgent()
        response_plan = [
            {"action_type": "block_ip", "target": "10.0.0.1"},
            {"action_type": "isolate_host", "target": "web01"},
        ]
        rollback = agent._generate_rollback_plan(response_plan)
        assert len(rollback) == 2
        assert rollback[0]["action"] == "unblock_ip"
        assert rollback[1]["action"] == "reconnect_host"

    def test_create_approval_request(self):
        agent = SilverResponseAgent()
        policy = {"tenant_policy": {"approval_timeout_minutes": 10}}
        actions = [{"action_type": "block_ip", "target": "10.0.0.1"}]

        request = agent._create_approval_request(
            "incident-123", "alert-456", actions, policy
        )
        assert request["incident_id"] == "incident-123"
        assert request["alert_id"] == "alert-456"
        assert request["status"] == "pending"
        assert "expires_at" in request
