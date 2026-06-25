"""
Silver Analysis Agent

Deep alert analysis with OpenCTI correlation and attack path reasoning.
Builds comprehensive attack narratives and MITRE mappings.

OSCAR Phase: Collect + Analyze - gather evidence, interpret patterns
"""

from typing import Any, Dict, List, Optional
from cobalto.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from cobalto.agent.state import AlertState, Severity, InvestigationState
from cobalto.agent.prompts import ANALYSIS_SYSTEM_PROMPT
from cobalto.agent.analysis_tools import opencti_query, misp_correlate, es_query
from cobalto.context.context_package import build_context
from cobalto.core.logging import get_logger
from cobalto.core.metrics import record_agent_execution
import time
import json

logger = get_logger(__name__)


class SilverAnalysisAgent(BaseAgent):
    """
    Silver Analysis Agent for deep alert analysis.

    Features:
    - OpenCTI GraphQL for threat intelligence correlation
    - MISP event correlation
    - Elasticsearch log search for related events
    - Attack path reasoning
    - MITRE ATT&CK technique mapping
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Silver Analysis Agent",
                agent_type=AgentType.ANALYSIS,
                description="Deep alert analysis with OpenCTI and MISP correlation",
                model="gpt-4o",
                temperature=0.1,
                tools=["opencti_query", "misp_correlate", "es_query"],
            )
        super().__init__(config)

    def get_system_prompt(self) -> str:
        """Get the system prompt for analysis agent."""
        return ANALYSIS_SYSTEM_PROMPT.template

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return [opencti_query, misp_correlate, es_query]

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute analysis logic with 5-layer context."""
        start_time = time.time()

        try:
            alert = input_data.get("alert", {})
            triage_result = input_data.get("triage_result", {})
            alert_id = input_data.get("alert_id", alert.get("id", "unknown"))
            tenant_id = input_data.get("tenant_id", "default")
            incident_id = input_data.get("incident_id", alert_id)

            logger.info(
                "silver_analysis_started",
                alert_id=alert_id,
                tenant_id=tenant_id,
            )

            # Build 5-layer context package
            context_package = await build_context(
                incident_id=incident_id,
                agent_type="analysis",
                tenant_id=tenant_id,
                alert_data=alert,
            )

            # Correlate with threat intelligence
            threat_intel = await self._correlate_threat_intel(alert, triage_result)

            # Search for related logs
            related_logs = await self._search_related_logs(alert, triage_result)

            # Build attack narrative
            attack_narrative = self._build_attack_narrative(
                alert, triage_result, threat_intel, related_logs
            )

            # Map to MITRE ATT&CK
            mitre_mapping = await self._map_mitre_techniques(
                alert, triage_result, threat_intel
            )

            # Assess risk
            risk_assessment = self._assess_risk(
                alert, triage_result, threat_intel, mitre_mapping
            )

            # Generate recommendations
            recommendations = self._generate_recommendations(
                alert, triage_result, threat_intel, mitre_mapping, risk_assessment
            )

            duration = time.time() - start_time

            # Record metrics
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "success",
                duration,
            )

            logger.info(
                "silver_analysis_complete",
                alert_id=alert_id,
                risk_score=risk_assessment.get("risk_score", 0),
                mitre_techniques=len(mitre_mapping.get("techniques", [])),
                duration=duration,
            )

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "alert_id": alert_id,
                    "attack_narrative": attack_narrative,
                    "threat_intel": threat_intel,
                    "related_logs_summary": self._summarize_logs(related_logs),
                    "mitre_mapping": mitre_mapping,
                    "risk_assessment": risk_assessment,
                    "recommendations": recommendations,
                    "context_summary": context_package.to_prompt_context(),
                    "raw_alert": alert,
                    "triage_result": triage_result,
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
            logger.exception("silver_analysis_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    async def _correlate_threat_intel(
        self, alert: Dict[str, Any], triage_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate alert with threat intelligence sources."""
        indicators = self._extract_indicators(alert)
        correlations = {
            "opencti": [],
            "misp": [],
            "threat_actors": [],
            "campaigns": [],
        }

        # Query OpenCTI for each indicator
        for indicator in indicators[:3]:  # Limit to 3 indicators
            try:
                result = await opencti_query.ainvoke({
                    "query_type": "indicator",
                    "search_term": indicator["value"],
                    "limit": 5,
                })
                if isinstance(result, str):
                    parsed = json.loads(result) if result.startswith("{") else {}
                    correlations["opencti"].append({
                        "indicator": indicator["value"],
                        "data": parsed,
                    })
            except Exception as e:
                logger.error("opencti_correlation_failed", indicator=indicator["value"], error=str(e))

        # Correlate with MISP
        for indicator in indicators[:2]:  # Limit to 2
            try:
                result = await misp_correlate.ainvoke({
                    "ioc_type": indicator["type"],
                    "ioc_value": indicator["value"],
                })
                if isinstance(result, str):
                    parsed = json.loads(result) if result.startswith("{") else {}
                    correlations["misp"].append({
                        "indicator": indicator["value"],
                        "data": parsed,
                    })
            except Exception as e:
                logger.error("misp_correlation_failed", indicator=indicator["value"], error=str(e))

        return correlations

    async def _search_related_logs(
        self, alert: Dict[str, Any], triage_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Search for related logs in Elasticsearch."""
        related_logs = {
            "same_source_ip": [],
            "same_user": [],
            "same_host": [],
            "time_correlated": [],
        }

        # Search for logs from same source IP
        source_ip = alert.get("source_ip")
        if source_ip:
            try:
                result = await es_query.ainvoke({
                    "index": "wazuh-*",
                    "query": f'source.ip: "{source_ip}"',
                    "time_range": "24h",
                    "limit": 20,
                })
                if isinstance(result, str):
                    parsed = json.loads(result) if result.startswith("{") else {}
                    related_logs["same_source_ip"] = parsed.get("results", [])
            except Exception as e:
                logger.error("es_query_failed", field="source_ip", error=str(e))

        # Search for logs from same user
        user_name = alert.get("user_name")
        if user_name:
            try:
                result = await es_query.ainvoke({
                    "index": "wazuh-*",
                    "query": f'user.name: "{user_name}"',
                    "time_range": "24h",
                    "limit": 20,
                })
                if isinstance(result, str):
                    parsed = json.loads(result) if result.startswith("{") else {}
                    related_logs["same_user"] = parsed.get("results", [])
            except Exception as e:
                logger.error("es_query_failed", field="user_name", error=str(e))

        return related_logs

    def _build_attack_narrative(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        threat_intel: Dict[str, Any],
        related_logs: Dict[str, Any],
    ) -> str:
        """Build a comprehensive attack narrative."""
        parts = []

        # Start with alert type
        alert_type = triage_result.get("alert_type", "unknown")
        parts.append(f"This is a {alert_type} alert.")

        # Add source information
        source_ip = alert.get("source_ip")
        if source_ip:
            parts.append(f"The activity originates from IP address {source_ip}.")

        # Add threat intel context
        opencti_data = threat_intel.get("opencti", [])
        if opencti_data:
            parts.append(f"Threat intelligence indicates this may be associated with known malicious activity.")

        # Add related activity
        same_ip_count = len(related_logs.get("same_source_ip", []))
        if same_ip_count > 1:
            parts.append(f"We observed {same_ip_count} related events from the same source in the last 24 hours.")

        # Add MITRE context if available
        mitre_techniques = triage_result.get("mitre_mapping", {}).get("techniques", [])
        if mitre_techniques:
            technique_names = [t.get("name", "") for t in mitre_techniques[:3]]
            parts.append(f"The activity matches MITRE ATT&CK techniques: {', '.join(technique_names)}.")

        return " ".join(parts) if parts else "Alert analysis in progress."

    async def _map_mitre_techniques(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        threat_intel: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map alert to MITRE ATT&CK techniques."""
        # Get techniques from triage
        triage_techniques = triage_result.get("mitre_mapping", {}).get("techniques", [])

        # Query OpenCTI for attack patterns
        try:
            alert_type = triage_result.get("alert_type", "unknown")
            result = await opencti_query.ainvoke({
                "query_type": "attack_pattern",
                "search_term": alert_type,
                "limit": 5,
            })
            if isinstance(result, str):
                parsed = json.loads(result) if result.startswith("{") else {}
                attack_patterns = parsed.get("attackPatterns", {}).get("edges", [])
                for pattern in attack_patterns:
                    node = pattern.get("node", {})
                    triage_techniques.append({
                        "technique_id": node.get("x_mitre_id", ""),
                        "name": node.get("name", ""),
                        "tactics": [t.get("name", "") for t in node.get("x_mitre_tactics", [])],
                        "source": "opencti",
                    })
        except Exception as e:
            logger.error("mitre_mapping_failed", error=str(e))

        # Deduplicate by technique_id
        seen = set()
        unique_techniques = []
        for t in triage_techniques:
            tid = t.get("technique_id", "")
            if tid and tid not in seen:
                seen.add(tid)
                unique_techniques.append(t)

        return {
            "techniques": unique_techniques,
            "tactics": self._extract_tactics(unique_techniques),
            "coverage_score": min(1.0, len(unique_techniques) / 10.0),
        }

    def _assess_risk(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        threat_intel: Dict[str, Any],
        mitre_mapping: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Assess risk based on all available context."""
        risk_score = 0
        risk_factors = []

        # Base severity
        severity = triage_result.get("severity", "informational")
        severity_scores = {
            "critical": 90,
            "high": 70,
            "medium": 50,
            "low": 30,
            "informational": 10,
        }
        risk_score += severity_scores.get(severity, 10)
        if severity in ("critical", "high"):
            risk_factors.append(f"High severity alert ({severity})")

        # MITRE technique risk
        techniques = mitre_mapping.get("techniques", [])
        if len(techniques) > 3:
            risk_score += 15
            risk_factors.append(f"Multiple MITRE techniques matched ({len(techniques)})")

        # Threat intel correlation
        if threat_intel.get("opencti"):
            risk_score += 20
            risk_factors.append("Correlated with threat intelligence")

        # Normalize to 0-100
        risk_score = min(100, risk_score)

        # Determine risk level
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "requires_immediate_action": risk_level in ("critical", "high"),
        }

    def _generate_recommendations(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        threat_intel: Dict[str, Any],
        mitre_mapping: Dict[str, Any],
        risk_assessment: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate response recommendations."""
        recommendations = []

        # Add containment recommendations based on risk
        if risk_assessment.get("requires_immediate_action"):
            recommendations.append({
                "action": "isolate_host",
                "target": alert.get("host_name", "unknown"),
                "risk_level": "high",
                "rationale": "High risk alert requires immediate containment",
                "requires_approval": True,
            })

        # Add investigation recommendations
        for technique in mitre_mapping.get("techniques", [])[:3]:
            recommendations.append({
                "action": "investigate",
                "target": technique.get("name", "unknown"),
                "risk_level": "low",
                "rationale": f"Investigate MITRE technique: {technique.get('name', '')}",
                "requires_approval": False,
            })

        # Add enrichment recommendations
        source_ip = alert.get("source_ip")
        if source_ip:
            recommendations.append({
                "action": "enrich_indicator",
                "target": source_ip,
                "risk_level": "low",
                "rationale": "Enrich source IP for additional context",
                "requires_approval": False,
            })

        return recommendations

    def _extract_indicators(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators from alert."""
        indicators = []
        for field in ["source_ip", "destination_ip", "user_name", "host_name"]:
            if alert.get(field):
                indicators.append({
                    "type": "ip" if "ip" in field else "hostname" if "host" in field else "user",
                    "value": alert[field],
                    "field": field,
                })
        return indicators

    def _extract_tactics(self, techniques: List[Dict[str, Any]]) -> List[str]:
        """Extract unique tactics from techniques."""
        tactics = set()
        for t in techniques:
            for tactic in t.get("tactics", []):
                tactics.add(tactic)
        return list(tactics)

    def _summarize_logs(self, related_logs: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize related logs."""
        return {
            "same_source_ip_count": len(related_logs.get("same_source_ip", [])),
            "same_user_count": len(related_logs.get("same_user", [])),
            "same_host_count": len(related_logs.get("same_host", [])),
            "time_correlated_count": len(related_logs.get("time_correlated", [])),
        }
