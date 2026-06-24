"""
Mock services for testing.
Provides in-memory implementations of external services.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel
import json


class MockWazuh:
    """Mock Wazuh SIEM for testing."""

    def __init__(self):
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.rules: List[Dict[str, Any]] = []

    def add_agent(self, agent_id: str, data: Dict[str, Any]) -> None:
        """Add a mock agent."""
        self.agents[agent_id] = {
            "id": agent_id,
            "name": data.get("name", f"agent-{agent_id}"),
            "ip": data.get("ip", "192.168.1.100"),
            "status": data.get("status", "active"),
            "version": data.get("version", "4.7.0"),
            **data,
        }

    def add_alert(self, alert: Dict[str, Any]) -> None:
        """Add a mock alert."""
        self.alerts.append({
            "id": f"alert-{len(self.alerts) + 1}",
            "timestamp": datetime.utcnow().isoformat(),
            **alert,
        })

    def get_agents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all agents."""
        return list(self.agents.values())[:limit]

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent by ID."""
        return self.agents.get(agent_id)

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts."""
        return sorted(
            self.alerts,
            key=lambda x: x.get("timestamp", ""),
            reverse=True,
        )[:limit]

    def active_response(self, agent_id: str, command: str) -> Dict[str, Any]:
        """Mock active response."""
        return {
            "status": "success",
            "agent_id": agent_id,
            "command": command,
            "message": f"Active response executed on {agent_id}",
        }


class MockOpenCTI:
    """Mock OpenCTI for testing."""

    def __init__(self):
        self.indicators: Dict[str, Dict[str, Any]] = {}
        self.threat_actors: Dict[str, Dict[str, Any]] = {}
        self.attack_patterns: Dict[str, Dict[str, Any]] = {}
        self.relationships: List[Dict[str, Any]] = []

    def add_indicator(self, indicator_id: str, data: Dict[str, Any]) -> None:
        """Add a mock indicator."""
        self.indicators[indicator_id] = {
            "id": indicator_id,
            "name": data.get("name", f"indicator-{indicator_id}"),
            "pattern": data.get("pattern", ""),
            "pattern_type": data.get("pattern_type", "stix"),
            "confidence": data.get("confidence", 50),
            **data,
        }

    def add_threat_actor(self, actor_id: str, data: Dict[str, Any]) -> None:
        """Add a mock threat actor."""
        self.threat_actors[actor_id] = {
            "id": actor_id,
            "name": data.get("name", f"actor-{actor_id}"),
            "description": data.get("description", ""),
            "aliases": data.get("aliases", []),
            **data,
        }

    def add_attack_pattern(self, pattern_id: str, data: Dict[str, Any]) -> None:
        """Add a mock attack pattern."""
        self.attack_patterns[pattern_id] = {
            "id": pattern_id,
            "name": data.get("name", f"pattern-{pattern_id}"),
            "description": data.get("description", ""),
            "x_mitre_id": data.get("x_mitre_id", ""),
            **data,
        }

    def get_indicator(self, indicator_id: str) -> Optional[Dict[str, Any]]:
        """Get indicator by ID."""
        return self.indicators.get(indicator_id)

    def search_indicators(self, search: str) -> List[Dict[str, Any]]:
        """Search indicators."""
        results = []
        for indicator in self.indicators.values():
            if search.lower() in indicator.get("name", "").lower():
                results.append(indicator)
        return results

    def get_threat_actor(self, actor_id: str) -> Optional[Dict[str, Any]]:
        """Get threat actor by ID."""
        return self.threat_actors.get(actor_id)

    def execute_query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a mock GraphQL query."""
        return {"data": {"serverInfo": {"version": "5.6.0"}}}


class MockTheHive:
    """Mock TheHive for testing."""

    def __init__(self):
        self.cases: Dict[str, Dict[str, Any]] = {}
        self.alerts: Dict[str, Dict[str, Any]] = {}
        self.observables: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}

    def create_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a mock case."""
        case_id = f"case-{len(self.cases) + 1}"
        self.cases[case_id] = {
            "_id": case_id,
            "caseId": case_id,
            "title": case_data.get("title", "Untitled Case"),
            "description": case_data.get("description", ""),
            "severity": case_data.get("severity", 2),
            "status": case_data.get("status", "Open"),
            "createdAt": datetime.utcnow().isoformat(),
            **case_data,
        }
        return self.cases[case_id]

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get case by ID."""
        return self.cases.get(case_id)

    def update_case(self, case_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update a case."""
        if case_id in self.cases:
            self.cases[case_id].update(update_data)
            return self.cases[case_id]
        return None

    def create_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a mock alert."""
        alert_id = f"alert-{len(self.alerts) + 1}"
        self.alerts[alert_id] = {
            "_id": alert_id,
            "alertId": alert_id,
            "title": alert_data.get("title", "Untitled Alert"),
            "description": alert_data.get("description", ""),
            "severity": alert_data.get("severity", 2),
            "status": alert_data.get("status", "New"),
            "createdAt": datetime.utcnow().isoformat(),
            **alert_data,
        }
        return self.alerts[alert_id]

    def add_observable(self, case_id: str, observable_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an observable to a case."""
        obs_id = f"obs-{len(self.observables) + 1}"
        self.observables[obs_id] = {
            "_id": obs_id,
            "caseId": case_id,
            "dataType": observable_data.get("dataType", "ip"),
            "data": observable_data.get("data", ""),
            "message": observable_data.get("message", ""),
            **observable_data,
        }
        return self.observables[obs_id]

    def create_task(self, case_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a task."""
        task_id = f"task-{len(self.tasks) + 1}"
        self.tasks[task_id] = {
            "_id": task_id,
            "caseId": case_id,
            "title": task_data.get("title", "Untitled Task"),
            "status": task_data.get("status", "Waiting"),
            **task_data,
        }
        return self.tasks[task_id]

    def get_metrics(self) -> Dict[str, Any]:
        """Get mock metrics."""
        return {
            "totalCases": len(self.cases),
            "openCases": len([c for c in self.cases.values() if c.get("status") == "Open"]),
            "totalAlerts": len(self.alerts),
        }


class MockCortex:
    """Mock Cortex for testing."""

    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.analyzers: List[Dict[str, Any]] = [
            {"id": "abuseipdb", "name": "AbuseIPDB", "dataType": ["ip"]},
            {"id": "virustotal", "name": "VirusTotal", "dataType": ["ip", "domain", "hash"]},
            {"id": "shodan", "name": "Shodan", "dataType": ["ip"]},
        ]

    def analyze_observable(
        self,
        observable_type: str,
        observable_value: str,
        analyzers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Mock analyze observable."""
        job_id = f"job-{len(self.jobs) + 1}"
        self.jobs[job_id] = {
            "id": job_id,
            "dataType": observable_type,
            "data": observable_value,
            "status": "Success",
            "report": {
                "summary": {"taxonomies": [{"level": "info", "predicate": "Verdict", "value": "Clean"}]},
            },
        }
        return self.jobs[job_id]

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job by ID."""
        return self.jobs.get(job_id)

    def list_analyzers(self, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List analyzers."""
        if data_type:
            return [a for a in self.analyzers if data_type in a.get("dataType", [])]
        return self.analyzers


class MockSlack:
    """Mock Slack for testing."""

    def __init__(self):
        self.messages: List[Dict[str, Any]] = []
        self.approval_requests: Dict[str, Dict[str, Any]] = {}

    def send_message(self, channel: str, text: str, blocks: Optional[List] = None) -> Dict[str, Any]:
        """Mock send message."""
        msg = {
            "channel": channel,
            "text": text,
            "blocks": blocks,
            "ts": datetime.utcnow().timestamp(),
        }
        self.messages.append(msg)
        return {"ok": True, "ts": msg["ts"]}

    def send_approval_request(
        self,
        channel: str,
        request_id: str,
        action_type: str,
        description: str,
    ) -> Dict[str, Any]:
        """Mock send approval request."""
        self.approval_requests[request_id] = {
            "channel": channel,
            "action_type": action_type,
            "description": description,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
        }
        return {"ok": True, "request_id": request_id}

    def approve_request(self, request_id: str) -> Dict[str, Any]:
        """Mock approve request."""
        if request_id in self.approval_requests:
            self.approval_requests[request_id]["status"] = "approved"
            return {"ok": True}
        return {"ok": False, "error": "Request not found"}

    def get_messages(self, channel: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get messages."""
        if channel:
            return [m for m in self.messages if m.get("channel") == channel]
        return self.messages


class MockQdrant:
    """Mock Qdrant for testing."""

    def __init__(self):
        self.collections: Dict[str, List[Dict[str, Any]]] = {}

    def create_collection(self, name: str, vector_size: int = 1536) -> bool:
        """Create a collection."""
        self.collections[name] = []
        return True

    def insert_points(self, collection: str, points: List[Dict[str, Any]]) -> bool:
        """Insert points."""
        if collection not in self.collections:
            self.collections[collection] = []
        self.collections[collection].extend(points)
        return True

    def search(
        self,
        collection: str,
        query_vector: List[float],
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Mock search."""
        if collection not in self.collections:
            return []

        # Return mock results
        return [
            {
                "id": str(i),
                "score": 0.9 - (i * 0.1),
                "payload": {"content": f"Mock result {i}"},
            }
            for i in range(min(limit, len(self.collections[collection])))
        ]

    def delete_collection(self, name: str) -> bool:
        """Delete a collection."""
        if name in self.collections:
            del self.collections[name]
            return True
        return False


class MockVault:
    """Mock HashiCorp Vault for testing."""

    def __init__(self):
        self.secrets: Dict[str, Dict[str, Any]] = {}
        self.leases: Dict[str, Dict[str, Any]] = {}

    def write_secret(self, path: str, data: Dict[str, Any]) -> bool:
        """Write a secret."""
        self.secrets[path] = data
        return True

    def read_secret(self, path: str) -> Optional[Dict[str, Any]]:
        """Read a secret."""
        return self.secrets.get(path)

    def delete_secret(self, path: str) -> bool:
        """Delete a secret."""
        if path in self.secrets:
            del self.secrets[path]
            return True
        return False

    def generate_database_credentials(self, role: str) -> Dict[str, str]:
        """Generate mock database credentials."""
        return {
            "username": f"user_{role}",
            "password": "mock_password_123",
            "lease_id": f"lease-{len(self.leases) + 1}",
            "lease_duration": 3600,
        }

    def generate_api_key(self, service: str) -> Dict[str, Any]:
        """Generate a mock API key."""
        import os
        api_key = os.urandom(16).hex()
        self.secrets[f"api-keys/{service}"] = {"key": api_key}
        return {"key": api_key}