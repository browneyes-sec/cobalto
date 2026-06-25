"""
Layer 1: Semantic Context

What business entities are involved?
asset_name, criticality, tenant_name, sla_tier
"""

from typing import Any, Dict, Optional
import structlog

logger = structlog.get_logger(__name__)


class SemanticLayer:
    """Loads business context for the incident."""

    # Asset criticality mapping based on hostname patterns
    CRITICALITY_PATTERNS = {
        "critical": ["dc", "domain", "ad", "pdc", "bdc", "sql", "database", "db", "erp", "crm"],
        "high": ["web", "app", "api", "server", "mail", "exchange"],
        "medium": ["workstation", "laptop", "desktop", "pc"],
        "low": ["printer", "scanner", "iot", "camera"],
    }

    async def load(
        self,
        tenant_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Load semantic context."""
        return {
            "tenant_id": tenant_id,
            "tenant_name": await self._get_tenant_name(tenant_id),
            "sla_tier": await self._get_sla_tier(tenant_id),
            "asset_criticality": self._get_asset_criticality(alert_data),
            "business_hours": self._is_business_hours(),
            "escalation_contacts": await self._get_escalation_contacts(tenant_id),
            "department": await self._get_department(tenant_id, alert_data),
            "compliance_requirements": await self._get_compliance_requirements(tenant_id),
        }

    async def _get_tenant_name(self, tenant_id: str) -> str:
        """Get tenant name from database."""
        # TODO: Query PostgreSQL tenant_service
        # For now, return a placeholder
        return f"tenant-{tenant_id}"

    async def _get_sla_tier(self, tenant_id: str) -> str:
        """Get SLA tier for tenant."""
        # TODO: Query PostgreSQL for SLA config
        # SLA tiers: premium, standard, basic
        return "standard"

    def _get_asset_criticality(self, alert_data: Optional[Dict[str, Any]]) -> str:
        """Determine asset criticality from alert data."""
        if not alert_data:
            return "unknown"

        host = alert_data.get("host_name", "").lower()
        if not host:
            return "medium"

        # Check against criticality patterns
        for criticality, patterns in self.CRITICALITY_PATTERNS.items():
            for pattern in patterns:
                if pattern in host:
                    return criticality

        return "medium"

    def _is_business_hours(self) -> bool:
        """Check if current time is within business hours."""
        from datetime import datetime
        hour = datetime.utcnow().hour
        # Business hours: 8 AM - 6 PM UTC
        return 8 <= hour <= 18

    async def _get_escalation_contacts(self, tenant_id: str) -> list:
        """Get escalation contacts for tenant."""
        # TODO: Query PostgreSQL
        return []

    async def _get_department(self, tenant_id: str, alert_data: Optional[Dict[str, Any]]) -> str:
        """Get department from alert or tenant config."""
        if alert_data:
            # Try to extract from user or host
            user = alert_data.get("user_name", "")
            if "admin" in user.lower():
                return "it"
            if "finance" in user.lower():
                return "finance"
        return "general"

    async def _get_compliance_requirements(self, tenant_id: str) -> list:
        """Get compliance requirements for tenant."""
        # TODO: Query PostgreSQL
        # Common: PCI-DSS, HIPAA, SOC2, GDPR, SOX
        return ["SOC2"]
