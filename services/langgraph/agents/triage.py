"""
Triage Agent for initial alert assessment.
Parses alerts, extracts IOCs, and determines severity.
"""

from typing import Any, Dict, List, Optional
from cobalto.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from cobalto.agent.state import AlertState, Severity, AlertStatus
from cobalto.agent.prompts import TRIAGE_SYSTEM_PROMPT
from cobalto.core.logging import get_logger
from cobalto.core.metrics import record_agent_execution
import time

logger = get_logger(__name__)


class TriageAgent(BaseAgent):
    """Agent for initial alert triage."""

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Triage Agent",
                agent_type=AgentType.TRIAGE,
                description="Initial alert assessment and IOC extraction",
                model="gpt-4o-mini",
                temperature=0.0,
            )
        super().__init__(config)

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return TRIAGE_SYSTEM_PROMPT.template

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return []

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute triage logic."""
        start_time = time.time()

        try:
            alert = input_data.get("alert", {})
            alert_id = input_data.get("alert_id", alert.get("id", "unknown"))

            # Extract key information
            triage_result = self._extract_triage_info(alert)

            # Determine severity
            severity = self._assess_severity(alert, triage_result)

            # Extract indicators
            indicators = self._extract_indicators(alert)

            # Generate investigation steps
            investigation_steps = self._generate_investigation_steps(alert, triage_result)

            duration = time.time() - start_time
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "success",
                duration,
            )

            logger.info(
                "triage_complete",
                alert_id=alert_id,
                severity=severity.value,
                indicators_count=len(indicators),
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
                    "investigation_steps": investigation_steps,
                    "confidence": triage_result.get("confidence", 0.7),
                    "raw_alert": alert,
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
            logger.exception("triage_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

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

    def _generate_investigation_steps(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
    ) -> List[str]:
        """Generate investigation steps."""
        steps = []

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

        return steps