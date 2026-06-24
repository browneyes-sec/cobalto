"""
Integration clients for external services.
Provides unified interfaces for Wazuh, TheHive, Slack, Cortex, and OpenCTI.
"""

from typing import Any, Dict, List, Optional
from abc import ABC, abstractmethod
import httpx
from ..core.logging import get_logger
from ..core.metrics import record_external_request

logger = get_logger(__name__)


class Integration(ABC):
    """Base class for service integrations."""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=30.0,
            )
        return self._client

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Make an HTTP request."""
        client = await self._get_client()
        start_time = __import__("time").time()
        try:
            response = await client.request(method, path, **kwargs)
            duration = __import__("time").time() - start_time

            record_external_request(
                "integration",
                self.__class__.__name__,
                path,
                str(response.status_code),
                duration,
            )

            response.raise_for_status()
            return response.json()
        except Exception as e:
            duration = __import__("time").time() - start_time
            record_external_request(
                "integration",
                self.__class__.__name__,
                path,
                "error",
                duration,
            )
            logger.exception("integration_request_failed", service=self.__class__.__name__, path=path, error=str(e))
            raise

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class WazuhIntegration(Integration):
    """Integration with Wazuh SIEM."""

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        super().__init__(base_url)
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    async def _get_client(self) -> httpx.AsyncClient:
        """Get client with basic auth."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=30.0,
            )
        return self._client

    async def get_agents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all agents."""
        response = await self._request("GET", "/agents", params={"limit": limit})
        return response.get("data", [])

    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Get agent details."""
        return await self._request("GET", f"/agents/{agent_id}")

    async def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        sort: str = "-timestamp",
    ) -> List[Dict[str, Any]]:
        """Get alerts."""
        response = await self._request(
            "GET",
            "/alerts",
            params={"limit": limit, "offset": offset, "sort": sort},
        )
        return response.get("data", [])

    async def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Get alert details."""
        return await self._request("GET", f"/alerts/{alert_id}")

    async def get_rules(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get detection rules."""
        response = await self._request("GET", "/rules", params={"limit": limit})
        return response.get("data", [])

    async def active_response(
        self,
        agent_id: str,
        command: str,
        arguments: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute active response on an agent."""
        return await self._request(
            "PUT",
            f"/active-response/{agent_id}",
            json={"command": command, "arguments": arguments or []},
        )

    async def get_sca_results(self, agent_id: str) -> Dict[str, Any]:
        """Get SCA (Security Configuration Assessment) results."""
        return await self._request("GET", f"/sca/{agent_id}")

    async def get_vulnerabilities(self, agent_id: str) -> Dict[str, Any]:
        """Get vulnerabilities for an agent."""
        return await self._request("GET", f"/vulnerability/{agent_id}")


class TheHiveIntegration(Integration):
    """Integration with TheHive case management."""

    async def create_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new case."""
        return await self._request("POST", "/api/v1/case", json=case_data)

    async def get_case(self, case_id: str) -> Dict[str, Any]:
        """Get case details."""
        return await self._request("GET", f"/api/v1/case/{case_id}")

    async def update_case(self, case_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a case."""
        return await self._request("PATCH", f"/api/v1/case/{case_id}", json=update_data)

    async def close_case(self, case_id: str) -> Dict[str, Any]:
        """Close a case."""
        return await self._request("PATCH", f"/api/v1/case/{case_id}", json={"status": "Resolved"})

    async def create_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert."""
        return await self._request("POST", "/api/v1/alert", json=alert_data)

    async def create_observable(self, case_id: str, observable_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an observable to a case."""
        return await self._request("POST", f"/api/v1/case/{case_id}/observable", json=observable_data)

    async def create_task(self, case_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a task in a case."""
        return await self._request("POST", f"/api/v1/case/{case_id}/task", json=task_data)

    async def add_comment(self, case_id: str, comment: str) -> Dict[str, Any]:
        """Add a comment to a case."""
        return await self._request("POST", f"/api/v1/case/{case_id}/comment", json={"message": comment})

    async def get_metrics(self) -> Dict[str, Any]:
        """Get case management metrics."""
        return await self._request("GET", "/api/v1/metrics")


class SlackIntegration(Integration):
    """Integration with Slack for notifications."""

    async def send_message(
        self,
        channel: str,
        text: str,
        blocks: Optional[List[Dict[str, Any]]] = None,
        thread_ts: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a message to a Slack channel."""
        payload = {
            "channel": channel,
            "text": text,
        }
        if blocks:
            payload["blocks"] = blocks
        if thread_ts:
            payload["thread_ts"] = thread_ts

        return await self._request("POST", "/api/chat.postMessage", json=payload)

    async def send_alert(
        self,
        channel: str,
        alert_id: str,
        severity: str,
        title: str,
        description: str,
        source_ip: Optional[str] = None,
        actions: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Send an alert notification with actions."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Security Alert: {title}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID:*\n{alert_id}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{source_ip or 'N/A'}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{description}"},
            },
        ]

        if actions:
            action_blocks = []
            for action in actions:
                action_blocks.append({
                    "type": "button",
                    "text": {"type": "plain_text", "text": action.get("text", "Action")},
                    "action_id": action.get("action_id", "action"),
                    "value": action.get("value", ""),
                })
            blocks.append({
                "type": "actions",
                "elements": action_blocks,
            })

        return await self.send_message(channel, f"Security Alert: {title}", blocks)

    async def send_approval_request(
        self,
        channel: str,
        request_id: str,
        action_type: str,
        description: str,
        timeout_minutes: int = 10,
    ) -> Dict[str, Any]:
        """Send an approval request."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔒 Action Requires Approval",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Request ID:*\n{request_id}"},
                    {"type": "mrkdwn", "text": f"*Action Type:*\n{action_type}"},
                    {"type": "mrkdwn", "text": f"*Timeout:*\n{timeout_minutes} minutes"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{description}"},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve"},
                        "style": "primary",
                        "action_id": "approve",
                        "value": request_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject"},
                        "style": "danger",
                        "action_id": "reject",
                        "value": request_id,
                    },
                ],
            },
        ]

        return await self.send_message(channel, "Action Requires Approval", blocks)


class CortexIntegration(Integration):
    """Integration with Cortex for observable enrichment."""

    async def analyze_observable(
        self,
        observable_type: str,
        observable_value: str,
        analyzers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Analyze an observable."""
        payload = {
            "dataType": observable_type,
            "data": observable_value,
        }
        if analyzers:
            payload["analyzers"] = analyzers

        return await self._request("POST", "/api/analyzer/run", json=payload)

    async def get_analyzer(self, analyzer_id: str) -> Dict[str, Any]:
        """Get analyzer details."""
        return await self._request("GET", f"/api/analyzer/{analyzer_id}")

    async def list_analyzers(self, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List available analyzers."""
        params = {}
        if data_type:
            params["dataType"] = data_type
        return await self._request("GET", "/api/analyzer", params=params)

    async def get_job(self, job_id: str) -> Dict[str, Any]:
        """Get analysis job details."""
        return await self._request("GET", f"/api/job/{job_id}")

    async def get_report(self, job_id: str) -> Dict[str, Any]:
        """Get analysis report."""
        return await self._request("GET", f"/api/job/{job_id}/report")


class OpenCTIIntegration(Integration):
    """Integration with OpenCTI for threat intelligence."""

    async def query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a GraphQL query."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        return await self._request("POST", "/graphql", json=payload)

    async def get_indicator(self, indicator_id: str) -> Dict[str, Any]:
        """Get an indicator."""
        query = """
        query GetIndicator($id: ID!) {
            indicator(id: $id) {
                id
                name
                pattern
                pattern_type
                valid_from
                confidence
                markingDefinitions {
                    id
                    definition_type
                }
            }
        }
        """
        return await self.query(query, {"id": indicator_id})

    async def search_indicators(
        self,
        search: str,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Search for indicators."""
        query = """
        query SearchIndicators($search: String, $first: Int) {
            indicators(search: $search, first: $first) {
                edges {
                    node {
                        id
                        name
                        pattern
                        pattern_type
                        confidence
                    }
                }
            }
        }
        """
        return await self.query(query, {"search": search, "first": limit})

    async def get_mitre_technique(self, technique_id: str) -> Dict[str, Any]:
        """Get a MITRE ATT&CK technique."""
        query = """
        query GetAttackPattern($id: ID!) {
            attackPattern(id: $id) {
                id
                name
                description
                x_mitre_id
                x_mitre_tactics {
                    id
                    name
                }
            }
        }
        """
        return await self.query(query, {"id": technique_id})

    async def get_threat_actor(self, actor_id: str) -> Dict[str, Any]:
        """Get a threat actor."""
        query = """
        query GetThreatActor($id: ID!) {
            threatActor(id: $id) {
                id
                name
                description
                aliases
                first_seen
                last_seen
                goals
                sophistication
            }
        }
        """
        return await self.query(query, {"id": actor_id})

    async def correlate_indicators(
        self,
        indicators: List[str],
    ) -> Dict[str, Any]:
        """Correlate multiple indicators."""
        query = """
        query CorrelateIndicators($indicators: [String!]!) {
            correlateIndicators(indicators: $indicators) {
                stixCoreRelationships {
                    id
                    relationship_type
                    source {
                        id
                        name
                    }
                    target {
                        id
                        name
                    }
                }
            }
        }
        """
        return await self.query(query, {"indicators": indicators})