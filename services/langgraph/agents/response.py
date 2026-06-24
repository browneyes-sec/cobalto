"""
Response Agent for generating response actions.
Creates containment and remediation plans.
"""

from typing import Any, Dict, List, Optional
from frameworks.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from frameworks.agent.state import ActionType
from frameworks.agent.prompts import RESPONSE_SYSTEM_PROMPT
from frameworks.core.logging import get_logger
from frameworks.core.metrics import record_agent_execution
import time

logger = get_logger(__name__)


class ResponseAgent(BaseAgent):
    """Agent for generating response actions."""

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Response Agent",
                agent_type=AgentType.RESPONSE,
                description="Generate and execute response actions",
                model="gpt-4o",
                temperature=0.0,
                requires_approval=True,
            )
        super().__init__(config)

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return RESPONSE_SYSTEM_PROMPT.template

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return []

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute response generation logic."""
        start_time = time.time()

        try:
            alert = input_data.get("alert", {})
            analysis = input_data.get("analysis", {})
            enrichment_data = input_data.get("enrichment_data", {})
            alert_id = input_data.get("alert_id", alert.get("id", "unknown"))

            # Generate containment actions
            containment_actions = self._generate_containment_actions(
                alert, analysis, enrichment_data
            )

            # Generate remediation actions
            remediation_actions = self._generate_remediation_actions(
                alert, analysis
            )

            # Determine approval requirements
            approval_required = self._determine_approval_requirements(
                containment_actions, remediation_actions
            )

            # Create rollback plan
            rollback_plan = self._create_rollback_plan(
                containment_actions, remediation_actions
            )

            # Prioritize actions
            prioritized_actions = self._prioritize_actions(
                containment_actions, remediation_actions
            )

            duration = time.time() - start_time
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "success",
                duration,
            )

            logger.info(
                "response_generated",
                alert_id=alert_id,
                containment_count=len(containment_actions),
                remediation_count=len(remediation_actions),
            )

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "alert_id": alert_id,
                    "containment_actions": containment_actions,
                    "remediation_actions": remediation_actions,
                    "approval_required": approval_required,
                    "rollback_plan": rollback_plan,
                    "prioritized_actions": prioritized_actions,
                    "priority": self._determine_priority(alert, analysis),
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
            logger.exception("response_generation_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    def _generate_containment_actions(
        self,
        alert: Dict[str, Any],
        analysis: Dict[str, Any],
        enrichment_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate containment actions."""
        actions = []

        source_ip = alert.get("source_ip")
        dest_ip = alert.get("destination_ip")
        user = alert.get("user_name")
        host = alert.get("host_name")

        # Block malicious IP
        if source_ip:
            actions.append({
                "type": ActionType.BLOCK_IP.value,
                "target": source_ip,
                "description": f"Block IP address {source_ip}",
                "requires_approval": True,
                "risk_level": "high",
            })

        # Isolate compromised host
        if host:
            actions.append({
                "type": ActionType.ISOLATE_HOST.value,
                "target": host,
                "description": f"Isolate host {host} from network",
                "requires_approval": True,
                "risk_level": "high",
            })

        # Disable compromised user
        if user:
            actions.append({
                "type": ActionType.DISABLE_USER.value,
                "target": user,
                "description": f"Disable user account {user}",
                "requires_approval": True,
                "risk_level": "medium",
            })

        return actions

    def _generate_remediation_actions(
        self,
        alert: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate remediation actions."""
        actions = []

        alert_type = analysis.get("alert_type", "unknown")

        if alert_type == "brute-force":
            actions.extend([
                {
                    "type": "reset_password",
                    "target": alert.get("user_name", "affected_user"),
                    "description": "Reset affected user passwords",
                    "requires_approval": True,
                    "risk_level": "low",
                },
                {
                    "type": "enable_mfa",
                    "target": "all_users",
                    "description": "Enable multi-factor authentication",
                    "requires_approval": False,
                    "risk_level": "low",
                },
            ])
        elif alert_type == "malware":
            actions.extend([
                {
                    "type": "quarantine_file",
                    "target": alert.get("file_path", "malware_file"),
                    "description": "Quarantine detected malware",
                    "requires_approval": False,
                    "risk_level": "low",
                },
                {
                    "type": "scan_system",
                    "target": alert.get("host_name", "affected_host"),
                    "description": "Full system scan for persistence",
                    "requires_approval": False,
                    "risk_level": "low",
                },
            ])
        elif alert_type == "ransomware":
            actions.extend([
                {
                    "type": "isolate_network",
                    "target": "affected_segment",
                    "description": "Isolate affected network segment",
                    "requires_approval": True,
                    "risk_level": "high",
                },
                {
                    "type": "restore_backup",
                    "target": alert.get("host_name", "affected_host"),
                    "description": "Restore from clean backup",
                    "requires_approval": True,
                    "risk_level": "medium",
                },
            ])

        return actions

    def _determine_approval_requirements(
        self,
        containment_actions: List[Dict[str, Any]],
        remediation_actions: List[Dict[str, Any]],
    ) -> List[str]:
        """Determine which actions require approval."""
        approval_required = []

        for action in containment_actions + remediation_actions:
            if action.get("requires_approval", False):
                approval_required.append(action["type"])

        return approval_required

    def _create_rollback_plan(
        self,
        containment_actions: List[Dict[str, Any]],
        remediation_actions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Create a rollback plan for executed actions."""
        rollback_plan = []

        for action in containment_actions:
            if action["type"] == ActionType.BLOCK_IP.value:
                rollback_plan.append({
                    "action": "unblock_ip",
                    "target": action["target"],
                    "description": f"Unblock IP address {action['target']}",
                })
            elif action["type"] == ActionType.ISOLATE_HOST.value:
                rollback_plan.append({
                    "action": "reconnect_host",
                    "target": action["target"],
                    "description": f"Reconnect host {action['target']} to network",
                })
            elif action["type"] == ActionType.DISABLE_USER.value:
                rollback_plan.append({
                    "action": "enable_user",
                    "target": action["target"],
                    "description": f"Enable user account {action['target']}",
                })

        return rollback_plan

    def _prioritize_actions(
        self,
        containment_actions: List[Dict[str, Any]],
        remediation_actions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Prioritize actions by risk level and urgency."""
        all_actions = containment_actions + remediation_actions

        # Sort by risk level
        risk_order = {"high": 0, "medium": 1, "low": 2}
        all_actions.sort(key=lambda x: risk_order.get(x.get("risk_level", "low"), 2))

        return all_actions

    def _determine_priority(
        self,
        alert: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> str:
        """Determine response priority."""
        severity = alert.get("severity", "medium").lower()
        risk_score = analysis.get("risk_assessment", {}).get("risk_score", 50)

        if severity == "critical" or risk_score >= 80:
            return "immediate"
        elif severity == "high" or risk_score >= 60:
            return "high"
        elif severity == "medium" or risk_score >= 40:
            return "medium"
        else:
            return "low"