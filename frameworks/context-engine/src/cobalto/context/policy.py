"""
Layer 4: Policy Context

What is the agent allowed to do?
allowed_actions[], autonomy_level, tenant_policy
"""

from typing import Any, Dict, List, Optional
import structlog

logger = structlog.get_logger(__name__)


class PolicyLayer:
    """Loads agent permissions and tenant policies."""

    # Default autonomy levels per agent type (DTP 5.1)
    AGENT_AUTONOMY = {
        "triage": "high",         # Auto-runs, no approval
        "analysis": "high",       # Auto-runs, no approval
        "threat_intel": "high",   # Read-only, no approval
        "response": "medium",     # Low-risk auto, high-risk approval
        "hunt": "high",           # Read-only, no approval
        "documentation": "high",  # Auto-runs, no approval
        "supervisor": "orchestrator",  # Not autonomous
    }

    # Actions requiring approval (DTP 5.1)
    HIGH_RISK_ACTIONS = [
        "isolate_host",
        "block_ip",
        "disable_user",
        "quarantine_file",
    ]

    # Default allowed actions per agent type
    DEFAULT_ALLOWED_ACTIONS = {
        "triage": [
            "enrich_indicator",
            "search_mitre",
            "search_opencti",
            "create_case",
            "send_notification",
        ],
        "analysis": [
            "enrich_indicator",
            "search_mitre",
            "search_opencti",
            "create_case",
            "add_observable",
            "send_notification",
        ],
        "threat_intel": [
            "search_mitre",
            "search_opencti",
            "correlate_indicators",
        ],
        "response": [
            "enrich_indicator",
            "search_mitre",
            "create_case",
            "add_observable",
            "send_notification",
            "isolate_host",
            "block_ip",
            "disable_user",
            "quarantine_file",
        ],
        "hunt": [
            "search_mitre",
            "search_opencti",
            "execute_query",
        ],
        "documentation": [
            "create_case",
            "add_artifact",
            "send_notification",
        ],
    }

    # Rate limits per autonomy level
    RATE_LIMITS = {
        "high": {
            "max_calls_per_minute": 30,
            "max_tokens_per_hour": 100000,
            "max_cost_per_day": 5.0,
        },
        "medium": {
            "max_calls_per_minute": 20,
            "max_tokens_per_hour": 50000,
            "max_cost_per_day": 2.0,
        },
        "low": {
            "max_calls_per_minute": 10,
            "max_tokens_per_hour": 20000,
            "max_cost_per_day": 1.0,
        },
    }

    async def load(self, tenant_id: str, agent_type: str) -> Dict[str, Any]:
        """Load policy context."""
        logger.info(
            "loading_policy_context",
            tenant_id=tenant_id,
            agent_type=agent_type,
        )

        autonomy_level = self.AGENT_AUTONOMY.get(agent_type, "low")
        allowed_actions = await self._get_allowed_actions(tenant_id, agent_type)
        tenant_policy = await self._get_tenant_policy(tenant_id)
        rate_limits = self._get_rate_limits(autonomy_level)

        return {
            "agent_type": agent_type,
            "autonomy_level": autonomy_level,
            "allowed_actions": allowed_actions,
            "high_risk_actions": self.HIGH_RISK_ACTIONS,
            "requires_approval": agent_type == "response",
            "tenant_policy": tenant_policy,
            "rate_limits": rate_limits,
            "can_auto_respond": autonomy_level == "high" and agent_type != "response",
        }

    async def _get_allowed_actions(self, tenant_id: str, agent_type: str) -> List[str]:
        """Get allowed actions for agent type and tenant."""
        # TODO: Query PostgreSQL for tenant-specific allowed actions
        # For now, return defaults
        return self.DEFAULT_ALLOWED_ACTIONS.get(agent_type, [])

    async def _get_tenant_policy(self, tenant_id: str) -> Dict[str, Any]:
        """Get tenant-specific policy."""
        # TODO: Query PostgreSQL
        return {
            "max_auto_response_actions": 5,
            "approval_timeout_minutes": 10,
            "notification_channels": ["slack"],
            "business_hours_only_response": False,
            "require_justification": True,
        }

    def _get_rate_limits(self, autonomy_level: str) -> Dict[str, int]:
        """Get rate limits for autonomy level."""
        return self.RATE_LIMITS.get(autonomy_level, self.RATE_LIMITS["low"])

    def is_action_allowed(self, action: str, allowed_actions: List[str]) -> bool:
        """Check if an action is allowed."""
        return action in allowed_actions

    def requires_approval(self, action: str) -> bool:
        """Check if an action requires approval."""
        return action in self.HIGH_RISK_ACTIONS
