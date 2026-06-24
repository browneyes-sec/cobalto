"""
Threat Intelligence Agent for correlating with threat intel data.
Queries OpenCTI and identifies threat actors.
"""

from typing import Any, Dict, List, Optional
from cobalto.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from cobalto.agent.prompts import THREAT_INTEL_SYSTEM_PROMPT
from cobalto.core.logging import get_logger
from cobalto.core.metrics import record_agent_execution
import time

logger = get_logger(__name__)


class ThreatIntelAgent(BaseAgent):
    """Agent for threat intelligence correlation."""

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Threat Intel Agent",
                agent_type=AgentType.THREAT_INTEL,
                description="Threat intelligence correlation and actor identification",
                model="gpt-4o",
                temperature=0.1,
            )
        super().__init__(config)

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return THREAT_INTEL_SYSTEM_PROMPT.template

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return []

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute threat intel logic."""
        start_time = time.time()

        try:
            alert = input_data.get("alert", {})
            indicators = input_data.get("indicators", [])
            mitre_techniques = input_data.get("mitre_techniques", [])
            alert_id = input_data.get("alert_id", alert.get("id", "unknown"))

            # Query threat intel
            threat_intel_results = self._query_threat_intel(indicators)

            # Identify threat actors
            threat_actors = self._identify_threat_actors(threat_intel_results, mitre_techniques)

            # Assess threat level
            threat_level = self._assess_threat_level(threat_intel_results, threat_actors)

            # Generate recommendations
            recommendations = self._generate_recommendations(
                threat_intel_results, threat_actors, threat_level
            )

            duration = time.time() - start_time
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "success",
                duration,
            )

            logger.info(
                "threat_intel_complete",
                alert_id=alert_id,
                threat_level=threat_level,
                actors_count=len(threat_actors),
            )

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "alert_id": alert_id,
                    "threat_intel_results": threat_intel_results,
                    "threat_actors": threat_actors,
                    "threat_level": threat_level,
                    "recommendations": recommendations,
                    "confidence": 0.8,
                },
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "error",
                duration,
            )
            logger.exception("threat_intel_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    def _query_threat_intel(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Query threat intelligence sources."""
        results = []

        for indicator in indicators:
            indicator_type = indicator.get("type")
            value = indicator.get("value")

            # Simulate threat intel lookup
            # In production, this would query OpenCTI, VirusTotal, etc.
            results.append({
                "indicator": value,
                "type": indicator_type,
                "source": "threat-intel",
                "confidence": 75,
                "tags": ["malicious"],
            })

        return results

    def _identify_threat_actors(
        self,
        threat_intel_results: List[Dict[str, Any]],
        mitre_techniques: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify potential threat actors."""
        actors = []

        # Map techniques to known threat actor TTPs
        technique_ids = [t.get("id", "") for t in mitre_techniques]

        # Known threat actor profiles
        threat_actor_profiles = {
            "APT28": {
                "name": "APT28 (Fancy Bear)",
                "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm"],
                "sophistication": "high",
                "motivation": "espionage",
                "techniques": ["T1566", "T1059", "T1071"],
            },
            "APT29": {
                "name": "APT29 (Cozy Bear)",
                "aliases": ["Cozy Bear", "The Dukes"],
                "sophistication": "high",
                "motivation": "espionage",
                "techniques": ["T1110", "T1078", "T1059"],
            },
            "FIN7": {
                "name": "FIN7",
                "aliases": ["Carbanak", "Navigator"],
                "sophistication": "high",
                "motivation": "financial",
                "techniques": ["T1566", "T1059", "T1021"],
            },
        }

        for actor_name, profile in threat_actor_profiles.items():
            matching_techniques = set(technique_ids) & set(profile["techniques"])
            if matching_techniques:
                actors.append({
                    "name": profile["name"],
                    "aliases": profile["aliases"],
                    "sophistication": profile["sophistication"],
                    "motivation": profile["motivation"],
                    "confidence": len(matching_techniques) / len(profile["techniques"]) * 100,
                    "matching_techniques": list(matching_techniques),
                })

        return actors

    def _assess_threat_level(
        self,
        threat_intel_results: List[Dict[str, Any]],
        threat_actors: List[Dict[str, Any]],
    ) -> str:
        """Assess overall threat level."""
        if threat_actors:
            # Check for high-confidence actor matches
            high_confidence = [a for a in threat_actors if a.get("confidence", 0) > 70]
            if high_confidence:
                return "critical"
            return "high"

        # Check indicator confidence
        high_confidence_indicators = [
            r for r in threat_intel_results
            if r.get("confidence", 0) > 80
        ]
        if high_confidence_indicators:
            return "high"

        return "medium"

    def _generate_recommendations(
        self,
        threat_intel_results: List[Dict[str, Any]],
        threat_actors: List[Dict[str, Any]],
        threat_level: str,
    ) -> List[str]:
        """Generate recommendations based on threat intel."""
        recommendations = []

        if threat_level in ("critical", "high"):
            recommendations.extend([
                "Immediately block all identified IOCs",
                "Initiate incident response procedures",
                "Notify security leadership",
                "Begin threat hunting activities",
            ])

        if threat_actors:
            recommendations.append(
                f"Investigate potential activity by {threat_actors[0].get('name', 'unknown actor')}"
            )

        recommendations.extend([
            "Correlate with historical alerts",
            "Review network traffic for related activity",
            "Update detection rules based on TTPs",
        ])

        return recommendations