"""
Analysis Agent for deep alert investigation.
Correlates with MITRE ATT&CK and builds attack narratives.
"""

from typing import Any, Dict, List, Optional
from frameworks.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from frameworks.agent.state import InvestigationState, Severity
from frameworks.agent.prompts import ANALYSIS_SYSTEM_PROMPT
from frameworks.core.logging import get_logger
from frameworks.core.metrics import record_agent_execution
import time

logger = get_logger(__name__)


class AnalysisAgent(BaseAgent):
    """Agent for deep alert analysis."""

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Analysis Agent",
                agent_type=AgentType.ANALYSIS,
                description="Deep alert analysis and MITRE ATT&CK mapping",
                model="gpt-4o",
                temperature=0.1,
            )
        super().__init__(config)

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return ANALYSIS_SYSTEM_PROMPT.template

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return []

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute analysis logic."""
        start_time = time.time()

        try:
            alert = input_data.get("alert", {})
            triage_result = input_data.get("triage_result", {})
            enrichment_data = input_data.get("enrichment_data", {})
            alert_id = input_data.get("alert_id", alert.get("id", "unknown"))

            # Build attack narrative
            attack_narrative = self._build_attack_narrative(alert, triage_result, enrichment_data)

            # Map to MITRE ATT&CK
            mitre_mapping = self._map_mitre_techniques(alert, triage_result)

            # Assess risk
            risk_assessment = self._assess_risk(alert, triage_result, enrichment_data, mitre_mapping)

            # Generate recommendations
            recommendations = self._generate_recommendations(
                alert, triage_result, mitre_mapping, risk_assessment
            )

            duration = time.time() - start_time
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "success",
                duration,
            )

            logger.info(
                "analysis_complete",
                alert_id=alert_id,
                risk_score=risk_assessment["risk_score"],
                techniques_count=len(mitre_mapping["techniques"]),
            )

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "alert_id": alert_id,
                    "attack_narrative": attack_narrative,
                    "mitre_mapping": mitre_mapping,
                    "risk_assessment": risk_assessment,
                    "recommendations": recommendations,
                    "confidence": 0.85,
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
            logger.exception("analysis_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    def _build_attack_narrative(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        enrichment_data: Dict[str, Any],
    ) -> str:
        """Build an attack narrative."""
        alert_type = triage_result.get("alert_type", "unknown")
        source_ip = alert.get("source_ip", "unknown")
        dest_ip = alert.get("destination_ip", "unknown")
        user = alert.get("user_name")

        narratives = {
            "brute-force": (
                f"An external IP address {source_ip} attempted multiple authentication "
                f"attempts against {dest_ip}. This indicates a brute force attack "
                f"targeting {'user ' + user if user else 'multiple accounts'}. "
                f"The attacker may be attempting to gain unauthorized access."
            ),
            "malware": (
                f"Malware activity detected from {source_ip} to {dest_ip}. "
                f"The alert indicates potential malware execution or communication "
                f"with command and control infrastructure."
            ),
            "ransomware": (
                f"Ransomware behavior detected on {dest_ip}. The alert indicates "
                f"potential file encryption activity, which could lead to data loss "
                f"and system compromise. Immediate isolation recommended."
            ),
            "phishing": (
                f"A phishing attempt was detected targeting users. "
                f"The attack may have involved malicious links or attachments "
                f"designed to harvest credentials or deliver malware."
            ),
            "data-exfiltration": (
                f"Potential data exfiltration detected from {source_ip} to {dest_ip}. "
                f"The alert indicates unauthorized data transfer, which could result "
                f"in data breach."
            ),
            "lateral-movement": (
                f"Lateral movement detected from {source_ip} to {dest_ip}. "
                f"The attacker may have compromised an initial system and is now "
                f"attempting to move through the network."
            ),
        }

        return narratives.get(alert_type, (
            f"Security alert detected involving {source_ip} and {dest_ip}. "
            f"Further investigation required to determine the attack vector and impact."
        ))

    def _map_mitre_techniques(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Map to MITRE ATT&CK techniques."""
        alert_type = triage_result.get("alert_type", "unknown")

        technique_mapping = {
            "brute-force": {
                "techniques": [
                    {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
                    {"id": "T1110.001", "name": "Password Guessing", "tactic": "credential-access"},
                ],
                "tactics": ["credential-access"],
            },
            "malware": {
                "techniques": [
                    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
                    {"id": "T1204", "name": "User Execution", "tactic": "execution"},
                ],
                "tactics": ["execution", "persistence"],
            },
            "ransomware": {
                "techniques": [
                    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
                    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "impact"},
                ],
                "tactics": ["impact"],
            },
            "phishing": {
                "techniques": [
                    {"id": "T1566", "name": "Phishing", "tactic": "initial-access"},
                    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "initial-access"},
                ],
                "tactics": ["initial-access"],
            },
            "data-exfiltration": {
                "techniques": [
                    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
                    {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
                ],
                "tactics": ["exfiltration"],
            },
            "lateral-movement": {
                "techniques": [
                    {"id": "T1021", "name": "Remote Services", "tactic": "lateral-movement"},
                    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "lateral-movement"},
                ],
                "tactics": ["lateral-movement"],
            },
        }

        mapping = technique_mapping.get(alert_type, {
            "techniques": [],
            "tactics": [],
        })

        return {
            "techniques": mapping["techniques"],
            "tactics": mapping["tactics"],
            "confidence": 0.8 if mapping["techniques"] else 0.3,
        }

    def _assess_risk(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        enrichment_data: Dict[str, Any],
        mitre_mapping: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Assess risk score and factors."""
        risk_score = 50  # Base score
        risk_factors = []

        # Severity factor
        severity = alert.get("severity", "medium").lower()
        if severity == "critical":
            risk_score += 30
            risk_factors.append("Critical severity alert")
        elif severity == "high":
            risk_score += 20
            risk_factors.append("High severity alert")
        elif severity == "medium":
            risk_score += 10

        # IOC enrichment factor
        if enrichment_data:
            vt_score = enrichment_data.get("virustotal", {}).get("score", 0)
            if vt_score > 0.7:
                risk_score += 20
                risk_factors.append("High VirusTotal score")
            abuse_score = enrichment_data.get("abuseipdb", {}).get("score", 0)
            if abuse_score > 0.7:
                risk_score += 15
                risk_factors.append("High AbuseIPDB score")

        # MITRE technique factor
        techniques = mitre_mapping.get("techniques", [])
        if len(techniques) > 2:
            risk_score += 10
            risk_factors.append("Multiple MITRE techniques mapped")

        # Cap at 100
        risk_score = min(100, risk_score)

        return {
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "risk_level": "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low",
        }

    def _generate_recommendations(
        self,
        alert: Dict[str, Any],
        triage_result: Dict[str, Any],
        mitre_mapping: Dict[str, Any],
        risk_assessment: Dict[str, Any],
    ) -> List[str]:
        """Generate recommendations."""
        recommendations = []
        risk_level = risk_assessment.get("risk_level", "medium")

        if risk_level in ("critical", "high"):
            recommendations.append("Immediately isolate affected systems")
            recommendations.append("Block malicious IP addresses")
            recommendations.append("Reset affected user credentials")

        recommendations.extend([
            "Enrich indicators with threat intelligence",
            "Correlate with other alerts in the same timeframe",
            "Review network traffic for anomalies",
            "Check for persistence mechanisms",
            "Document investigation findings",
        ])

        return recommendations