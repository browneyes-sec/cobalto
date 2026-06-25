"""Tests for Silver Triage Agent."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from cobalto.agent.base_agent import AgentConfig, AgentType, AgentStatus
from cobalto.agent.state import Severity
from services.langgraph.agents.triage import SilverTriageAgent


class TestSilverTriageAgent:
    """Tests for SilverTriageAgent."""

    def test_agent_initialization(self):
        agent = SilverTriageAgent()
        assert agent.config.name == "Silver Triage Agent"
        assert agent.config.agent_type == AgentType.TRIAGE
        assert agent.config.temperature == 0.0
        assert "mitre_rag_search" in agent.config.tools
        assert "cortex_enrich" in agent.config.tools
        assert "vt_lookup" in agent.config.tools

    def test_agent_has_tools(self):
        agent = SilverTriageAgent()
        tools = agent.get_tools()
        assert len(tools) == 3
        tool_names = [t.name for t in tools]
        assert "mitre_rag_search" in tool_names
        assert "cortex_enrich" in tool_names
        assert "vt_lookup" in tool_names

    def test_system_prompt(self):
        agent = SilverTriageAgent()
        prompt = agent.get_system_prompt()
        assert "SOC Triage Agent" in prompt
        assert "Cobalto" in prompt

    def test_extract_triage_info(self):
        agent = SilverTriageAgent()
        alert = {
            "rule_id": "5712",
            "rule_description": "Brute force detected",
            "source": "wazuh",
        }
        result = agent._extract_triage_info(alert)
        assert result["alert_type"] == "brute-force"
        assert result["rule_id"] == "5712"
        assert result["confidence"] == 0.8

    def test_assess_severity_critical(self):
        agent = SilverTriageAgent()
        alert = {"severity": "critical"}
        triage_result = {"alert_type": "unknown"}
        result = agent._assess_severity(alert, triage_result)
        assert result == Severity.CRITICAL

    def test_assess_severity_high_rule_level(self):
        agent = SilverTriageAgent()
        alert = {"rule_level": 12}
        triage_result = {"alert_type": "unknown"}
        result = agent._assess_severity(alert, triage_result)
        assert result == Severity.CRITICAL

    def test_extract_indicators(self):
        agent = SilverTriageAgent()
        alert = {
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.1",
            "user_name": "admin",
            "host_name": "web01",
        }
        indicators = agent._extract_indicators(alert)
        assert len(indicators) == 4
        values = [i["value"] for i in indicators]
        assert "10.0.0.1" in values
        assert "admin" in values

    def test_generate_investigation_steps_brute_force(self):
        agent = SilverTriageAgent()
        alert = {}
        triage_result = {"alert_type": "brute-force"}
        mitre_result = {"techniques": []}
        steps = agent._generate_investigation_steps(alert, triage_result, mitre_result)
        assert len(steps) > 0
        assert any("authentication" in s.lower() for s in steps)

    def test_generate_investigation_steps_with_mitre(self):
        agent = SilverTriageAgent()
        alert = {}
        triage_result = {"alert_type": "unknown"}
        mitre_result = {
            "techniques": [
                {"name": "Credential Dumping"},
                {"name": "Pass the Hash"},
            ]
        }
        steps = agent._generate_investigation_steps(alert, triage_result, mitre_result)
        assert any("Credential Dumping" in s for s in steps)
        assert any("Pass the Hash" in s for s in steps)

    def test_build_mitre_query(self):
        agent = SilverTriageAgent()
        alert = {
            "rule_description": "Multiple failed login attempts",
            "event_type": "authentication",
        }
        triage_result = {"alert_type": "brute-force"}
        query = agent._build_mitre_query(alert, triage_result)
        assert "Multiple failed login attempts" in query
        assert "brute-force" in query
