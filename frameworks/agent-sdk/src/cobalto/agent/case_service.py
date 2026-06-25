"""
Case Service

TheHive case management integration for incident lifecycle.
Auto-creates cases from alerts and tracks SLA compliance.

DTP 3.3: Data Product - incidents, case-timeline
DTP 2.1: Incident Lifecycle capability
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import httpx
import structlog

logger = structlog.get_logger(__name__)


class CaseSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseStatus(str, Enum):
    NEW = "New"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


class CasePriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class CaseTemplate(BaseModel):
    """TheHive case template."""
    title: str
    description: str = ""
    severity: CaseSeverity = CaseSeverity.MEDIUM
    priority: CasePriority = CasePriority.P3
    tags: List[str] = []
    custom_fields: Dict[str, Any] = {}


class CaseService:
    """
    Case service for TheHive integration.

    Features:
    - Auto-create cases from alerts
    - SLA tracking
    - Case timeline management
    - Observable and artifact management
    """

    def __init__(
        self,
        thehive_url: str = "http://localhost:9000",
        thehive_token: Optional[str] = None,
        default_owner: str = "soc-team",
    ):
        self.thehive_url = thehive_url.rstrip("/")
        self.thehive_token = thehive_token
        self.default_owner = default_owner

    async def create_case(
        self,
        alert_id: str,
        tenant_id: str,
        title: str,
        description: str = "",
        severity: CaseSeverity = CaseSeverity.MEDIUM,
        priority: CasePriority = CasePriority.P3,
        tags: Optional[List[str]] = None,
        template: Optional[CaseTemplate] = None,
    ) -> Dict[str, Any]:
        """Create a new case in TheHive."""
        # Use template if provided
        if template:
            title = template.title
            description = template.description
            severity = template.severity
            priority = template.priority
            tags = template.tags or []

        # Add standard tags
        tags = tags or []
        tags.extend([f"tenant:{tenant_id}", f"alert:{alert_id}", "cobalto:auto"])

        case_data = {
            "title": title,
            "description": description,
            "severity": self._map_severity(severity),
            "priority": self._map_priority(priority),
            "tags": tags,
            "customFields": {
                "tenantId": {"string": tenant_id},
                "alertId": {"string": alert_id},
                "source": {"string": "cobalto"},
                "slaTier": {"string": "standard"},
            },
            "pap": 2,  # Permissible Actions Protocol
            "status": CaseStatus.NEW.value,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.thehive_url}/api/v1/case",
                    headers=self._get_headers(),
                    json=case_data,
                    timeout=30.0,
                )

                if response.status_code == 201:
                    case = response.json()
                    logger.info(
                        "case_created",
                        case_id=case.get("id"),
                        alert_id=alert_id,
                        tenant_id=tenant_id,
                        severity=severity.value,
                    )
                    return case
                else:
                    logger.error(
                        "case_creation_failed",
                        status_code=response.status_code,
                        alert_id=alert_id,
                    )
                    return {"error": f"TheHive returned {response.status_code}"}

        except Exception as e:
            logger.error("case_creation_failed", error=str(e), alert_id=alert_id)
            return {"error": str(e)}

    async def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get case details."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.thehive_url}/api/v1/case/{case_id}",
                    headers=self._get_headers(),
                    timeout=10.0,
                )

                if response.status_code == 200:
                    return response.json()
                return None

        except Exception as e:
            logger.error("get_case_failed", error=str(e), case_id=case_id)
            return None

    async def update_case(
        self,
        case_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update case details."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.patch(
                    f"{self.thehive_url}/api/v1/case/{case_id}",
                    headers=self._get_headers(),
                    json=updates,
                    timeout=10.0,
                )

                if response.status_code == 200:
                    logger.info("case_updated", case_id=case_id, updates=list(updates.keys()))
                    return response.json()
                return {"error": f"TheHive returned {response.status_code}"}

        except Exception as e:
            logger.error("case_update_failed", error=str(e), case_id=case_id)
            return {"error": str(e)}

    async def add_observable(
        self,
        case_id: str,
        observable_type: str,
        observable_value: str,
        data_type: str = "IP",
        message: str = "",
    ) -> Dict[str, Any]:
        """Add an observable to a case."""
        observable_data = {
            "dataType": data_type,
            "data": observable_value,
            "message": message,
            "tags": [],
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.thehive_url}/api/v1/case/{case_id}/observable",
                    headers=self._get_headers(),
                    json=observable_data,
                    timeout=10.0,
                )

                if response.status_code == 201:
                    logger.info(
                        "observable_added",
                        case_id=case_id,
                        type=observable_type,
                        value=observable_value,
                    )
                    return response.json()
                return {"error": f"TheHive returned {response.status_code}"}

        except Exception as e:
            logger.error("observable_add_failed", error=str(e), case_id=case_id)
            return {"error": str(e)}

    async def add_artifact(
        self,
        case_id: str,
        artifact_type: str,
        artifact_data: str,
        message: str = "",
    ) -> Dict[str, Any]:
        """Add an artifact to a case."""
        artifact = {
            "dataType": artifact_type,
            "data": artifact_data,
            "message": message,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.thehive_url}/api/v1/case/{case_id}/artifact",
                    headers=self._get_headers(),
                    json=artifact,
                    timeout=10.0,
                )

                if response.status_code == 201:
                    logger.info("artifact_added", case_id=case_id, type=artifact_type)
                    return response.json()
                return {"error": f"TheHive returned {response.status_code}"}

        except Exception as e:
            logger.error("artifact_add_failed", error=str(e), case_id=case_id)
            return {"error": str(e)}

    async def add_comment(
        self,
        case_id: str,
        message: str,
    ) -> Dict[str, Any]:
        """Add a comment to a case."""
        comment_data = {"message": message}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.thehive_url}/api/v1/case/{case_id}/comment",
                    headers=self._get_headers(),
                    json=comment_data,
                    timeout=10.0,
                )

                if response.status_code == 201:
                    logger.info("comment_added", case_id=case_id)
                    return response.json()
                return {"error": f"TheHive returned {response.status_code}"}

        except Exception as e:
            logger.error("comment_add_failed", error=str(e), case_id=case_id)
            return {"error": str(e)}

    async def close_case(
        self,
        case_id: str,
        resolution: str = "Resolved",
    ) -> Dict[str, Any]:
        """Close a case."""
        updates = {
            "status": CaseStatus.RESOLVED.value,
            "resolution": resolution,
        }
        return await self.update_case(case_id, updates)

    async def create_case_from_alert(
        self,
        alert_data: Dict[str, Any],
        tenant_id: str,
        triage_result: Dict[str, Any],
        analysis_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a case from alert with full context."""
        alert_id = alert_data.get("id", "unknown")
        severity = triage_result.get("severity", "medium")
        alert_type = triage_result.get("alert_type", "unknown")

        # Build title
        title = f"[{severity.upper()}] {alert_type.title()} - {alert_id}"

        # Build description
        description_parts = [
            f"## Alert Information",
            f"- **Alert ID:** {alert_id}",
            f"- **Tenant:** {tenant_id}",
            f"- **Type:** {alert_type}",
            f"- **Severity:** {severity}",
            f"",
        ]

        # Add indicators
        indicators = triage_result.get("indicators", [])
        if indicators:
            description_parts.append("## Indicators")
            for ind in indicators:
                description_parts.append(f"- {ind.get('type', 'unknown')}: {ind.get('value', 'unknown')}")
            description_parts.append("")

        # Add MITRE mapping
        mitre = triage_result.get("mitre_mapping", {})
        techniques = mitre.get("techniques", [])
        if techniques:
            description_parts.append("## MITRE ATT&CK")
            for t in techniques[:5]:
                description_parts.append(f"- {t.get('technique_id', '')}: {t.get('name', '')}")
            description_parts.append("")

        # Add investigation steps
        steps = triage_result.get("investigation_steps", [])
        if steps:
            description_parts.append("## Investigation Steps")
            for i, step in enumerate(steps, 1):
                description_parts.append(f"{i}. {step}")

        description = "\n".join(description_parts)

        # Create case
        case = await self.create_case(
            alert_id=alert_id,
            tenant_id=tenant_id,
            title=title,
            description=description,
            severity=CaseSeverity(severity) if severity in CaseSeverity.__members__.values() else CaseSeverity.MEDIUM,
            tags=[alert_type, f"alert:{alert_id}"],
        )

        # Add indicators as observables
        if "id" in case:
            for ind in indicators[:10]:  # Limit to 10 observables
                data_type = self._map_observable_type(ind.get("type", "unknown"))
                await self.add_observable(
                    case_id=case["id"],
                    observable_type=ind.get("type", "unknown"),
                    observable_value=ind.get("value", ""),
                    data_type=data_type,
                )

        return case

    def _map_severity(self, severity: CaseSeverity) -> int:
        """Map severity to TheHive format."""
        return {
            CaseSeverity.LOW: 1,
            CaseSeverity.MEDIUM: 2,
            CaseSeverity.HIGH: 3,
            CaseSeverity.CRITICAL: 4,
        }.get(severity, 2)

    def _map_priority(self, priority: CasePriority) -> int:
        """Map priority to TheHive format."""
        return {
            CasePriority.P1: 1,
            CasePriority.P2: 2,
            CasePriority.P3: 3,
            CasePriority.P4: 4,
        }.get(priority, 3)

    def _map_observable_type(self, indicator_type: str) -> str:
        """Map indicator type to TheHive observable type."""
        type_map = {
            "ip": "IP",
            "domain": "domain",
            "hash": "hash",
            "url": "url",
            "email": "email",
            "user": "user",
            "hostname": "hostname",
        }
        return type_map.get(indicator_type, "other")

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        if self.thehive_token:
            headers["Authorization"] = f"Bearer {self.thehive_token}"
        return headers
