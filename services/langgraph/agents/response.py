"""
Silver Response Agent

Incident response with approval gate and policy enforcement.
Generates response plans and executes approved actions.

OSCAR Phase: Report + Response - generate action plan for human approval
"""

from typing import Any, Dict, List, Optional
from cobalto.agent.base_agent import BaseAgent, AgentConfig, AgentType, AgentStatus, AgentResult
from cobalto.agent.state import AlertState, Severity, ResponseState, ActionType
from cobalto.agent.prompts import RESPONSE_SYSTEM_PROMPT
from cobalto.agent.response_tools import (
    n8n_execute, wazuh_active_response, firewall_block, slack_notify
)
from cobalto.context.context_package import build_context
from cobalto.core.logging import get_logger
from cobalto.core.metrics import record_agent_execution
import time
import json
from datetime import datetime, timedelta

logger = get_logger(__name__)


class SilverResponseAgent(BaseAgent):
    """
    Silver Response Agent for incident response.

    Features:
    - Response plan generation
    - Approval gate for high-risk actions
    - Policy enforcement
    - Rollback plan creation
    - N8N workflow execution
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        if config is None:
            config = AgentConfig(
                name="Silver Response Agent",
                agent_type=AgentType.RESPONSE,
                description="Incident response with approval gate",
                model="gpt-4o",
                temperature=0.0,
                tools=["n8n_execute", "wazuh_active_response", "firewall_block", "slack_notify"],
                requires_approval=True,
            )
        super().__init__(config)

    def get_system_prompt(self) -> str:
        """Get the system prompt for response agent."""
        return RESPONSE_SYSTEM_PROMPT.template

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return [n8n_execute, wazuh_active_response, firewall_block, slack_notify]

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Execute response logic with approval gate."""
        start_time = time.time()

        try:
            alert = input_data.get("alert", {})
            analysis_result = input_data.get("analysis_result", {})
            triage_result = input_data.get("triage_result", {})
            alert_id = input_data.get("alert_id", alert.get("id", "unknown"))
            tenant_id = input_data.get("tenant_id", "default")
            incident_id = input_data.get("incident_id", alert_id)

            logger.info(
                "silver_response_started",
                alert_id=alert_id,
                tenant_id=tenant_id,
            )

            # Build 5-layer context package
            context_package = await build_context(
                incident_id=incident_id,
                agent_type="response",
                tenant_id=tenant_id,
                alert_data=alert,
            )

            # Check if approval is required
            policy = context_package.policy
            requires_approval = policy.get("requires_approval", True)

            # Generate response plan
            response_plan = self._generate_response_plan(
                alert, analysis_result, triage_result, policy
            )

            # Categorize actions by risk level
            auto_actions = [a for a in response_plan if not a.get("requires_approval", False)]
            approval_required = [a for a in response_plan if a.get("requires_approval", False)]

            # Execute auto-actions (low risk)
            auto_results = []
            for action in auto_actions:
                result = await self._execute_action(action)
                auto_results.append(result)

            # Prepare approval request if needed
            approval_request = None
            if approval_required:
                approval_request = self._create_approval_request(
                    incident_id, alert_id, approval_required, policy
                )

            # Generate rollback plan
            rollback_plan = self._generate_rollback_plan(response_plan)

            duration = time.time() - start_time

            # Record metrics
            record_agent_execution(
                self.config.name,
                self.agent_type.value,
                "success",
                duration,
            )

            logger.info(
                "silver_response_complete",
                alert_id=alert_id,
                auto_actions=len(auto_actions),
                approval_required=len(approval_required),
                duration=duration,
            )

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.COMPLETED,
                output={
                    "alert_id": alert_id,
                    "response_plan": response_plan,
                    "auto_actions": auto_actions,
                    "auto_results": auto_results,
                    "approval_required": approval_required,
                    "approval_request": approval_request,
                    "rollback_plan": rollback_plan,
                    "requires_approval": requires_approval,
                    "context_summary": context_package.to_prompt_context(),
                    "raw_alert": alert,
                    "analysis_result": analysis_result,
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
            logger.exception("silver_response_failed", error=str(e))
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status=AgentStatus.FAILED,
                error=str(e),
                duration_seconds=duration,
            )

    def _generate_response_plan(
        self,
        alert: Dict[str, Any],
        analysis_result: Dict[str, Any],
        triage_result: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate response plan based on analysis."""
        plan = []

        # Get risk assessment
        risk_assessment = analysis_result.get("risk_assessment", {})
        risk_score = risk_assessment.get("risk_score", 0)

        # Get recommended actions
        recommendations = analysis_result.get("recommendations", [])

        for rec in recommendations:
            action = {
                "action_type": rec.get("action", "unknown"),
                "target": rec.get("target", "unknown"),
                "risk_level": rec.get("risk_level", "low"),
                "rationale": rec.get("rationale", ""),
                "requires_approval": self._requires_approval(rec.get("action", ""), policy),
                "priority": self._calculate_priority(rec, risk_score),
                "estimated_impact": self._estimate_impact(rec),
            }
            plan.append(action)

        # Add standard response actions based on alert type
        alert_type = triage_result.get("alert_type", "unknown")
        if alert_type == "brute-force":
            plan.extend(self._add_brute_force_actions(alert, risk_score))
        elif alert_type == "malware":
            plan.extend(self._add_malware_actions(alert, risk_score))
        elif alert_type == "ransomware":
            plan.extend(self._add_ransomware_actions(alert, risk_score))

        # Sort by priority
        plan.sort(key=lambda x: x.get("priority", 0), reverse=True)

        return plan

    def _requires_approval(self, action_type: str, policy: Dict[str, Any]) -> bool:
        """Check if action requires approval based on policy."""
        high_risk_actions = policy.get("high_risk_actions", [
            "isolate_host", "block_ip", "disable_user", "quarantine_file"
        ])
        return action_type in high_risk_actions

    def _calculate_priority(self, rec: Dict[str, Any], risk_score: int) -> int:
        """Calculate action priority."""
        priority = 0
        if rec.get("requires_approval"):
            priority += 10
        if risk_score >= 80:
            priority += 5
        elif risk_score >= 60:
            priority += 3
        return priority

    def _estimate_impact(self, rec: Dict[str, Any]) -> str:
        """Estimate action impact."""
        action_type = rec.get("action", "")
        if action_type in ["isolate_host", "block_ip"]:
            return "high"
        elif action_type in ["disable_user", "quarantine_file"]:
            return "medium"
        return "low"

    def _add_brute_force_actions(self, alert: Dict[str, Any], risk_score: int) -> List[Dict[str, Any]]:
        """Add brute-force specific response actions."""
        actions = []
        source_ip = alert.get("source_ip")

        if source_ip and risk_score >= 70:
            actions.append({
                "action_type": "block_ip",
                "target": source_ip,
                "risk_level": "high",
                "rationale": "Block source IP after multiple failed attempts",
                "requires_approval": True,
                "priority": 8,
                "estimated_impact": "high",
            })

        actions.append({
            "action_type": "enforce_lockout",
            "target": alert.get("user_name", "unknown"),
            "risk_level": "medium",
            "rationale": "Enforce account lockout policy",
            "requires_approval": False,
            "priority": 5,
            "estimated_impact": "medium",
        })

        return actions

    def _add_malware_actions(self, alert: Dict[str, Any], risk_score: int) -> List[Dict[str, Any]]:
        """Add malware specific response actions."""
        actions = []
        host_name = alert.get("host_name")

        if host_name and risk_score >= 60:
            actions.append({
                "action_type": "isolate_host",
                "target": host_name,
                "risk_level": "high",
                "rationale": "Isolate infected host to prevent lateral movement",
                "requires_approval": True,
                "priority": 9,
                "estimated_impact": "high",
            })

        actions.append({
            "action_type": "collect_evidence",
            "target": host_name or "unknown",
            "risk_level": "low",
            "rationale": "Collect forensic evidence before remediation",
            "requires_approval": False,
            "priority": 7,
            "estimated_impact": "low",
        })

        return actions

    def _add_ransomware_actions(self, alert: Dict[str, Any], risk_score: int) -> List[Dict[str, Any]]:
        """Add ransomware specific response actions."""
        actions = []
        host_name = alert.get("host_name")

        # Immediate isolation for ransomware
        if host_name:
            actions.append({
                "action_type": "isolate_host",
                "target": host_name,
                "risk_level": "critical",
                "rationale": "Immediate isolation required for ransomware",
                "requires_approval": True,
                "priority": 10,
                "estimated_impact": "high",
            })

        actions.append({
            "action_type": "notify_escalation",
            "target": "soc-manager",
            "risk_level": "low",
            "rationale": "Escalate ransomware incident to management",
            "requires_approval": False,
            "priority": 8,
            "estimated_impact": "low",
        })

        return actions

    async def _execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a response action."""
        action_type = action.get("action_type", "")
        target = action.get("target", "")

        try:
            if action_type == "block_ip":
                result = await firewall_block.ainvoke({
                    "ip_address": target,
                    "reason": action.get("rationale", "Security incident"),
                })
            elif action_type == "isolate_host":
                # TODO: Integrate with actual host isolation
                result = str({"status": "placeholder", "message": "Host isolation requires integration"})
            else:
                result = str({"status": "skipped", "message": f"Action {action_type} not implemented"})

            return {
                "action": action,
                "status": "executed",
                "result": result,
                "executed_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error("action_execution_failed", action=action_type, error=str(e))
            return {
                "action": action,
                "status": "failed",
                "error": str(e),
                "executed_at": datetime.utcnow().isoformat(),
            }

    def _create_approval_request(
        self,
        incident_id: str,
        alert_id: str,
        actions: List[Dict[str, Any]],
        policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create approval request for high-risk actions."""
        timeout_minutes = policy.get("tenant_policy", {}).get("approval_timeout_minutes", 10)

        return {
            "request_id": f"approval-{incident_id}-{int(time.time())}",
            "incident_id": incident_id,
            "alert_id": alert_id,
            "actions": actions,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=timeout_minutes)).isoformat(),
            "timeout_minutes": timeout_minutes,
            "notification_channels": policy.get("tenant_policy", {}).get("notification_channels", ["slack"]),
            "status": "pending",
        }

    def _generate_rollback_plan(self, response_plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate rollback plan for executed actions."""
        rollback = []

        for action in response_plan:
            action_type = action.get("action_type", "")
            target = action.get("target", "")

            if action_type == "block_ip":
                rollback.append({
                    "action": "unblock_ip",
                    "target": target,
                    "rationale": "Rollback IP block",
                })
            elif action_type == "isolate_host":
                rollback.append({
                    "action": "reconnect_host",
                    "target": target,
                    "rationale": "Rollback host isolation",
                })

        return rollback
