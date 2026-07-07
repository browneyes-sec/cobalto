"""Tests for Silver Analysis Agent."""

import pytest
from cobalto.agent.base_agent import AgentConfig, AgentType
from services.langgraph.agents.analysis import SilverAnalysisAgent


class TestSilverAnalysisAgent:
    """Tests for SilverAnalysisAgent."""

    def test_agent_initialization(self):
        agent = SilverAnalysisAgent()
        assert agent.config.name == "Silver Analysis Agent"
        assert agent.config.agent_type == AgentType.ANALYSIS
        assert agent.config.model == "gpt-4o"
        assert agent.config.temperature == 0.1

    def test_agent_has_tools(self):
        agent = SilverAnalysisAgent()
        tools = agent.get_tools()
        assert len(tools) == 3
        tool_names = [t.name for t in tools]
        assert "opencti_query" in tool_names
        assert "misp_correlate" in tool_names
        assert "es_query" in tool_names

    def test_system_prompt(self):
        agent = SilverAnalysisAgent()
        prompt = agent.get_system_prompt()
        assert "SOC Analysis Agent" in prompt
        assert "Cobalto" in prompt

    def test_extract_indicators(self):
        agent = SilverAnalysisAgent()
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

    def test_build_attack_narrative(self):
        agent = SilverAnalysisAgent()
        alert = {"source_ip": "10.0.0.1"}
        triage_result = {"alert_type": "brute-force"}
        threat_intel = {"opencti": []}
        related_logs = {"same_source_ip": [1, 2, 3]}

        narrative = agent._build_attack_narrative(
            alert, triage_result, threat_intel, related_logs
        )
        assert "brute-force" in narrative
        assert "10.0.0.1" in narrative
        assert "3" in narrative

    def test_assess_risk_critical(self):
        agent = SilverAnalysisAgent()
        triage_result = {"severity": "critical"}
        threat_intel = {"opencti": [{"data": {}}]}
        mitre_mapping = {"techniques": [{"name": "T1"}, {"name": "T2"}, {"name": "T3"}]}

        risk = agent._assess_risk({}, triage_result, threat_intel, mitre_mapping)
        assert risk["risk_score"] >= 80
        assert risk["risk_level"] == "critical"
        assert risk["requires_immediate_action"] is True

    def test_assess_risk_low(self):
        agent = SilverAnalysisAgent()
        triage_result = {"severity": "informational"}
        threat_intel = {"opencti": []}
        mitre_mapping = {"techniques": []}

        risk = agent._assess_risk({}, triage_result, threat_intel, mitre_mapping)
        assert risk["risk_score"] < 40
        assert risk["risk_level"] == "low"

    def test_extract_tactics(self):
        agent = SilverAnalysisAgent()
        techniques = [
            {"tactics": ["initial-access", "execution"]},
            {"tactics": ["execution", "persistence"]},
        ]
        tactics = agent._extract_tactics(techniques)
        assert "initial-access" in tactics
        assert "execution" in tactics
        assert "persistence" in tactics
