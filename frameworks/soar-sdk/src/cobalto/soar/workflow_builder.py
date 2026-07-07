"""
Workflow builder for n8n integration.
Creates n8n-compatible workflow definitions.
"""

from typing import Any, Dict, List, Optional, Callable
from pydantic import BaseModel, Field
from enum import Enum
import json
import uuid


class NodeType(str, Enum):
    WEBHOOK = "n8n-nodes-base.webhook"
    HTTP_REQUEST = "n8n-nodes-base.httpRequest"
    CODE = "n8n-nodes-base.code"
    IF = "n8n-nodes-base.if"
    SWITCH = "n8n-nodes-base.switch"
    SET = "n8n-nodes-base.set"
    FUNCTION = "n8n-nodes-base.function"
    SLACK = "n8n-nodes-base.slack"
    EMAIL = "n8n-nodes-base.emailSend"
    WAZUH = "n8n-nodes-base.wazuh"
    THEHIVE = "n8n-nodes-base.theHive"
    CORTEX = "n8n-nodes-base.cortex"
    LANGGRAPH = "n8n-nodes-base.langGraph"
    QDRANT = "n8n-nodes-base.qdrant"
    ELASTICSEARCH = "n8n-nodes-base.elasticsearch"


class NodePosition(BaseModel):
    """Position of a node in the workflow."""
    x: int
    y: int


class NodeParameter(BaseModel):
    """Parameter for a node."""
    name: str
    value: Any
    type: str = "string"


class WorkflowNode(BaseModel):
    """A node in an n8n workflow."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: NodeType
    type_version: int = 1
    position: NodePosition
    parameters: Dict[str, Any] = {}
    credentials: Optional[Dict[str, str]] = None
    disabled: bool = False


class Connection(BaseModel):
    """Connection between workflow nodes."""
    source_node: str
    target_node: str
    source_output: int = 0
    target_input: int = 0


class WorkflowEdge(BaseModel):
    """Edge in the workflow graph."""
    source: str
    target: str
    condition: Optional[str] = None


class WorkflowBuilder:
    """Builder for n8n-compatible workflows."""

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.nodes: List[WorkflowNode] = []
        self.connections: List[Connection] = []
        self.variables: Dict[str, Any] = {}
        self.settings: Dict[str, Any] = {
            "executionOrder": "v1",
            "saveManualExecutions": True,
            "callerPolicy": "workflowsFromSameOwner",
        }

    def add_webhook(
        self,
        name: str,
        path: str,
        method: str = "POST",
        authentication: str = "headerAuth",
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add a webhook trigger node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.WEBHOOK,
            position=position or NodePosition(x=250, y=300),
            parameters={
                "httpMethod": method,
                "path": path,
                "authentication": authentication,
                "responseMode": "responseNode",
            },
        )
        self.nodes.append(node)
        return self

    def add_http_request(
        self,
        name: str,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add an HTTP request node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.HTTP_REQUEST,
            position=position or NodePosition(x=500, y=300),
            parameters={
                "url": url,
                "method": method,
                "headers": headers or {},
                "body": body or {},
                "options": {
                    "response": {"response": {"responseFormat": "json"}},
                },
            },
        )
        self.nodes.append(node)
        return self

    def add_code(
        self,
        name: str,
        js_code: str,
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add a code node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.CODE,
            position=position or NodePosition(x=750, y=300),
            parameters={
                "jsCode": js_code,
            },
        )
        self.nodes.append(node)
        return self

    def add_if(
        self,
        name: str,
        conditions: List[Dict[str, Any]],
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add an IF node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.IF,
            position=position or NodePosition(x=1000, y=300),
            parameters={
                "conditions": conditions,
            },
        )
        self.nodes.append(node)
        return self

    def add_switch(
        self,
        name: str,
        rules: List[Dict[str, Any]],
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add a switch node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.SWITCH,
            position=position or NodePosition(x=1000, y=300),
            parameters={
                "rules": rules,
            },
        )
        self.nodes.append(node)
        return self

    def add_set(
        self,
        name: str,
        values: Dict[str, Any],
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add a set node to update data."""
        node = WorkflowNode(
            name=name,
            type=NodeType.SET,
            position=position or NodePosition(x=500, y=500),
            parameters={
                "values": values,
                "options": {},
            },
        )
        self.nodes.append(node)
        return self

    def add_slack_notification(
        self,
        name: str,
        channel: str,
        message: str,
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add a Slack notification node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.SLACK,
            position=position or NodePosition(x=1250, y=300),
            parameters={
                "channel": channel,
                "text": message,
                "otherOptions": {},
            },
            credentials={"slackApi": "Slack API"},
        )
        self.nodes.append(node)
        return self

    def add_langgraph_agent(
        self,
        name: str,
        url: str,
        agent_type: str,
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add a LangGraph agent node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.LANGGRAPH,
            position=position or NodePosition(x=750, y=300),
            parameters={
                "url": url,
                "agentType": agent_type,
                "options": {},
            },
        )
        self.nodes.append(node)
        return self

    def add_qdrant_search(
        self,
        name: str,
        url: str,
        collection: str,
        query: str,
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add a Qdrant vector search node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.QDRANT,
            position=position or NodePosition(x=750, y=500),
            parameters={
                "url": url,
                "collection": collection,
                "query": query,
                "options": {},
            },
        )
        self.nodes.append(node)
        return self

    def add_elasticsearch_search(
        self,
        name: str,
        url: str,
        index: str,
        query: str,
        position: Optional[NodePosition] = None,
    ) -> "WorkflowBuilder":
        """Add an Elasticsearch search node."""
        node = WorkflowNode(
            name=name,
            type=NodeType.ELASTICSEARCH,
            position=position or NodePosition(x=750, y=700),
            parameters={
                "url": url,
                "index": index,
                "query": query,
                "options": {},
            },
        )
        self.nodes.append(node)
        return self

    def connect(
        self,
        source: str,
        target: str,
        source_output: int = 0,
        target_input: int = 0,
    ) -> "WorkflowBuilder":
        """Connect two nodes."""
        self.connections.append(Connection(
            source_node=source,
            target_node=target,
            source_output=source_output,
            target_input=target_input,
        ))
        return self

    def set_variable(self, name: str, value: Any) -> "WorkflowBuilder":
        """Set a workflow variable."""
        self.variables[name] = value
        return self

    def build(self) -> Dict[str, Any]:
        """Build the n8n workflow definition."""
        # Build connections object
        connections = {}
        for conn in self.connections:
            if conn.source_node not in connections:
                connections[conn.source_node] = {"main": [[]]}
            while len(connections[conn.source_node]["main"]) <= conn.source_output:
                connections[conn.source_node]["main"].append([])
            connections[conn.source_node]["main"][conn.source_output].append({
                "node": conn.target_node,
                "type": "main",
                "index": conn.target_input,
            })

        return {
            "name": self.name,
            "nodes": [node.model_dump() for node in self.nodes],
            "connections": connections,
            "active": False,
            "settings": self.settings,
            "staticData": None,
            "tags": [],
            "triggerCount": 0,
            "updatedAt": None,
            "versionId": str(uuid.uuid4()),
        }

    def to_json(self, indent: int = 2) -> str:
        """Export workflow as JSON."""
        return json.dumps(self.build(), indent=indent)

    def save(self, filepath: str) -> None:
        """Save workflow to a file."""
        with open(filepath, "w") as f:
            f.write(self.to_json())