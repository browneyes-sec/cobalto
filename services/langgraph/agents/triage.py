"""
Silver Triage Agent

Enhanced Triage Agent with MITRE RAG and IOC enrichment tools.
Performs initial alert assessment with 5-layer context model.

OSCAR Phase: Orient - reads alert, enriches IOCs, scores severity
"""

from typing import Any, Dict, List, Optional
from cobalto.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from cobalto.agent.state import AlertState, Severity, AlertStatus
from cobalto.agent.prompts import TRIAGE_SYSTEM_PROMPT
from cobalto.agent.triage_tools import mitre_rag_search, cortex_enrich, vt_lookup
from cobalto.context.context_package import build_context
from cobalto.core.logging import get_logger
from cobalto.core.metrics import record_agent_execution
import time

logger = get_logger(__name__)


class SilverTriageAgent(BaseAgent):
    """
    Silver Triage Agent for initial alert assessment.

    Features:
    - MITRE ATT&CK RAG for technique mapping
    - IOC enrichment via Cortex
    - 5-layer context model integration
    - Severity assessment with business context
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Silver Triage Agent",
                agent_type=AgentType.TRIAGE,
                description="Initial alert assessment with MITRE RAG and IOC enrichment",
                model="gpt-4o-mini",
                temperature=0.0,
                tools=["mitre_rag_search", "cortex_enrich", "vt_lookup"],
            )
        super().__init__(config)

    def get_system_prompt(self) -> str:
        """Get the system prompt for triage agent."""
        return TRIAGE_SYSTEM_PROMPT.template

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return [mitre_rag_search, cortex_enrich, vt_lookup]

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute triage logic with 5-layer context."""
        start_time = time.time()

        try:
            alert = input_data.get("alert", {})
            alert_id = input_data.get("alert_id", alert.get("id", "unknown"))
            tenant_id = input_data.get("tenant_id", "default")
            incident_id = input_data.get("incident_id", alert_id)

            logger.info(
                "silver_triage_started",
                alert_id=alert_id,
                tenant_id=tenant_id,
            )

            # Build 5-layer context package
            context_package = await build_context(
                incident_id=incident_id,
                agent_type="triage",
                tenant_id=tenant_id,
                alert_data=alert,
            )

            # Extract key information
            triage_result = self._extract_triage_info(alert)

            # MITRE RAG enrichment
            mitre_result = await self._enrich_with_mitre(alert, triage_result)

            # IOC enrichment via Cortex
            ioc_results = await self._enrich_iocs(alert)

            # Determine severity with full context
            severity = self._assess_severity_with_context(
                alert, triage_result, mitre_result, ioc_results, context_package
            )

            # Extract indicators
            indicators = self._extract_indicators(alert)

            # Generate investigation steps with MITRE context
            investigation_steps = self._generate_investigation_steps(
                alert, triage_result, mitre_result
            )

            # Calculate confidence score
            confidence = self._calculate_confidence(
                triage_result, mitre_result, ioc_results
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
                "silver_triage_complete",
                alert_id=alert_id,
                severity=severity.value,
                indicators_count=len(indicators),
                mitre_techniques=len(mitre_result.get("techniques", [])),
                duration=duration,
            )

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "alert_id": alert_id,
                    "alert_type": triage_result.get("alert_type", "unknown"),
                    "severity": severity.value,
                    "indicators": indicators,
                    "mitre_mapping": mitre_result,
                    "ioc_enrichment": ioc_results,
                    "investigation_steps": investigation_steps,
                    "confidence": confidence,
                    "context_summary": context_package.to_prompt_context(),
                    "context_package_token_estimate": context_package.token_estimate,
                    "raw_alert": alert,
                },
                duration_seconds=duration,
                token_usage={"context_tokens": context_package.token_estimate},
            )

        except Exception as e:
            duration = time.time() - start_time
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "error",
                duration,
            )
            logger.exception("silver_triage_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    async def _enrich_with_mitre(
        self, alert: Dict[str, Any], triage_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrich alert with MITRE ATT&CK RAG."""
        try:
            query = self._build_mitre_query(alert, triage_result)
            result = await mitre_rag_search.ainvoke({"query": query, "top_k": 5})

            # Parse result
            if isinstance(result, str):
                import ast
                try:
                    techniques = ast.literal_eval(result)
                except (SyntaxError, ValueError):
                    techniques = []
            else:
                techniques = result

            return {"techniques": techniques}

        except Exception as e:
            logger.error("mitre_enrichment_failed", error=str(e))
            return {"techniques": []}

    async def _enrich_iocs(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich IOCs using Cortex."""
        results = {}

        for field in ["source_ip", "destination_ip"]:
            if alert.get(field):
                try:
                    result = await cortex_enrich.ainvoke({
                        "observable_type": "ip",
                        "observable_value": alert[field],
                    })

                    # Parse result
                    if isinstance(result, str):
                        import ast
                        try:
                            enrichment = ast.literal_eval(result)
                        except (SyntaxError, ValueError):
                            enrichment = {"raw": result}
                    else:
                        enrichment = result

                    results[alert[field]] = enrichment

                except Exception as e:
                    logger.error(
                        "ioc_enrichment_failed",
                        field=field,
                        value=alert[field],
                        error=str(e),
                    )
                    results[alert[field]] = {"error": str(e)}

        return results

    def _assess_severity_with_context(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        mitre_result: Dict[str, Any],
        ioc_results: Dict[str, Any],
        context_package,
    ) -> Severity:
        """Assess severity with full context from all 5 layers."""

        # Base severity from alert
        base_severity = self._assess_severity(alert, triage_result)

        # Boost if MITRE techniques match critical tactics
        critical_tactics = {
            "initial-access", "execution", "persistence",
            "privilege-escalation", "lateral-movement",
        }
        matched_tactics = set()
        for technique in mitre_result.get("techniques", []):
            for tactic in technique.get("tactics", []):
                tactic_id = tactic.get("tactic_id", "") if isinstance(tactic, dict) else str(tactic)
                matched_tactics.add(tactic_id)

        if critical_tactics & matched_tactics:
            if base_severity == Severity.MEDIUM:
                return Severity.HIGH
            elif base_severity == Severity.LOW:
                return Severity.MEDIUM

        # Boost if IOC enrichment shows malicious
        for ip, enrichment in ioc_results.items():
            if isinstance(enrichment, dict):
                if enrichment.get("malicious") or enrichment.get("threat_score", 0) > 70:
                    if base_severity == Severity.LOW:
                        return Severity.MEDIUM

        # Boost during business hours for critical assets
        if context_package.semantic.get("asset_criticality") == "critical":
            if base_severity == Severity.MEDIUM:
                return Severity.HIGH

        # Boost if alert velocity is high (burst detection)
        if context_package.operational.get("alert_velocity", {}).get("burst_detected"):
            if base_severity in (Severity.LOW, Severity.MEDIUM):
                return Severity.HIGH

        return base_severity

    def _extract_triage_info(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract triage information from alert."""
        rule_id = alert.get("rule_id", "")
        rule_desc = alert.get("rule_description", "")
        source = alert.get("source", "")

        # Determine alert type
        alert_type = "unknown"
        if "brute" in rule_desc.lower():
            alert_type = "brute-force"
        elif "malware" in rule_desc.lower():
            alert_type = "malware"
        elif "phishing" in rule_desc.lower():
            alert_type = "phishing"
        elif "ransomware" in rule_desc.lower():
            alert_type = "ransomware"
        elif "exfiltration" in rule_desc.lower():
            alert_type = "data-exfiltration"
        elif "lateral" in rule_desc.lower():
            alert_type = "lateral-movement"

        return {
            "alert_type": alert_type,
            "rule_id": rule_id,
            "rule_description": rule_desc,
            "source": source,
            "confidence": 0.8 if alert_type != "unknown" else 0.5,
        }

    def _assess_severity(self, alert: Dict[str, Any], triage_result: Dict[str, Any]) -> Severity:
        """Assess alert severity."""
        # Check explicit severity
        severity_str = alert.get("severity", "").lower()
        if severity_str in ("critical", "high"):
            return Severity.CRITICAL if severity_str == "critical" else Severity.HIGH
        elif severity_str == "medium":
            return Severity.MEDIUM
        elif severity_str == "low":
            return Severity.LOW

        # Assess based on rule level
        rule_level = alert.get("rule_level", 0)
        if rule_level >= 12:
            return Severity.CRITICAL
        elif rule_level >= 8:
            return Severity.HIGH
        elif rule_level >= 4:
            return Severity.MEDIUM
        elif rule_level >= 1:
            return Severity.LOW

        return Severity.INFORMATIONAL

    def _extract_indicators(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from alert."""
        indicators = []

        # IP addresses
        for field in ["source_ip", "destination_ip"]:
            if alert.get(field):
                indicators.append({
                    "type": "ip",
                    "value": alert[field],
                    "field": field,
                })

        # Usernames
        if alert.get("user_name"):
            indicators.append({
                "type": "user",
                "value": alert["user_name"],
                "field": "user_name",
            })

        # Hostnames
        if alert.get("host_name"):
            indicators.append({
                "type": "hostname",
                "value": alert["host_name"],
                "field": "host_name",
            })

        # Additional indicators from alert
        for ioc in alert.get("indicators", []):
            indicators.append(ioc)

        return indicators

    def _build_mitre_query(self, alert: Dict[str, Any], triage_result: Dict[str, Any]) -> str:
        """Build query for MITRE RAG search."""
        parts = []
        if alert.get("rule_description"):
            parts.append(alert["rule_description"])
        if triage_result.get("alert_type") != "unknown":
            parts.append(triage_result["alert_type"])
        if alert.get("event_type"):
            parts.append(alert["event_type"])
        return " ".join(parts) if parts else "security alert"

    def _generate_investigation_steps(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        mitre_result: Dict[str, Any],
    ) -> List[str]:
        """Generate investigation steps with MITRE context."""
        steps = []

        # Add MITRE-specific steps
        for technique in mitre_result.get("techniques", [])[:3]:
            name = technique.get("name", "unknown")
            steps.append(f"Investigate MITRE technique: {name}")

        # Add standard steps based on alert type
        alert_type = triage_result.get("alert_type", "unknown")
        if alert_type == "brute-force":
            steps.extend([
                "Check authentication logs for failed attempts",
                "Identify source IP reputation",
                "Check for successful logins after failures",
                "Review account lockout status",
            ])
        elif alert_type == "malware":
            steps.extend([
                "Analyze malware samples",
                "Check for lateral movement",
                "Identify C2 communications",
                "Review file integrity alerts",
            ])
        elif alert_type == "ransomware":
            steps.extend([
                "Isolate affected systems immediately",
                "Identify encryption scope",
                "Check backup integrity",
                "Review file system changes",
            ])
        elif alert_type == "phishing":
            steps.extend([
                "Analyze email headers",
                "Check for malicious attachments/links",
                "Identify affected users",
                "Review credential harvesting attempts",
            ])
        else:
            steps.extend([
                "Review alert details",
                "Enrich indicators",
                "Correlate with other alerts",
                "Determine impact scope",
            ])

        # Limit to 10 steps
        return steps[:10]

    def _calculate_confidence(
        self,
        triage_result: Dict[str, Any],
        mitre_result: Dict[str, Any],
        ioc_results: Dict[str, Any],
    ) -> float:
        """Calculate confidence score for triage."""
        scores = []

        # Base confidence from triage
        scores.append(triage_result.get("confidence", 0.5))

        # Boost if MITRE techniques found
        if mitre_result.get("techniques"):
            scores.append(0.8)

        # Boost if IOCs enriched
        if ioc_results:
            scores.append(0.7)

        return sum(scores) / len(scores) if scores else 0.5
