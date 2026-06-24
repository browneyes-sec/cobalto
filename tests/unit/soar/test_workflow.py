"""
Unit tests for SOAR SDK.
"""

import pytest
import json
from cobalto.soar.workflow_builder import WorkflowBuilder, NodePosition, NodeType
from cobalto.soar.webhook_handler import WebhookHandler, WebhookPayload, AlertSource, NormalizedAlert
from cobalto.soar.playbook import Playbook, PlaybookStep, PlaybookAction, ActionType, PlaybookEngine


class TestWorkflowBuilder:
    """Test workflow builder."""

    def test_builder_creation(self):
        """Test builder creation."""
        builder = WorkflowBuilder("test-workflow", "Test workflow")
        assert builder.name == "test-workflow"

    def test_add_webhook(self):
        """Test adding webhook node."""
        builder = WorkflowBuilder("test-workflow")
        builder.add_webhook("Webhook", "/alerts")
        assert len(builder.nodes) == 1
        assert builder.nodes[0].type == NodeType.WEBHOOK

    def test_add_http_request(self):
        """Test adding HTTP request node."""
        builder = WorkflowBuilder("test-workflow")
        builder.add_http_request("API Call", "https://api.example.com", method="POST")
        assert len(builder.nodes) == 1

    def test_add_code_node(self):
        """Test adding code node."""
        builder = WorkflowBuilder("test-workflow")
        builder.add_code("Process", "return items;")
        assert len(builder.nodes) == 1

    def test_connect_nodes(self):
        """Test connecting nodes."""
        builder = WorkflowBuilder("test-workflow")
        builder.add_webhook("Webhook", "/alerts")
        builder.add_code("Process", "return items;")
        builder.connect("Webhook", "Process")
        assert len(builder.connections) == 1

    def test_build_workflow(self):
        """Test workflow building."""
        builder = WorkflowBuilder("test-workflow", "Test")
        builder.add_webhook("Webhook", "/alerts")
        builder.add_code("Process", "return items;")
        builder.connect("Webhook", "Process")
        workflow = builder.build()
        assert workflow["name"] == "test-workflow"
        assert len(workflow["nodes"]) == 2

    def test_to_json(self):
        """Test JSON export."""
        builder = WorkflowBuilder("test-workflow")
        builder.add_webhook("Webhook", "/alerts")
        json_str = builder.to_json()
        data = json.loads(json_str)
        assert data["name"] == "test-workflow"


class TestWebhookHandler:
    """Test webhook handler."""

    def test_handler_creation(self):
        """Test handler creation."""
        handler = WebhookHandler(webhook_secret="test-secret")
        assert handler.webhook_secret == "test-secret"

    def test_signature_verification(self):
        """Test signature verification."""
        handler = WebhookHandler(webhook_secret="test-secret")
        import hmac
        import hashlib
        payload = b"test-payload"
        signature = hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
        assert handler.verify_signature(payload, signature) is True

    def test_wazuh_parser(self):
        """Test Wazuh alert parser."""
        handler = WebhookHandler()
        parser = handler.create_wazuh_parser()

        alert_data = {
            "data": {
                "id": 12345,
                "rule": {"id": 5712, "level": 8, "description": "Brute force"},
                "srcip": "203.0.113.45",
                "dstip": "192.168.1.100",
                "user": "admin",
            }
        }

        result = parser(alert_data)
        assert isinstance(result, NormalizedAlert)
        assert result.source == AlertSource.WAZUH
        assert result.source_ip == "203.0.113.45"

    def test_severity_mapping(self):
        """Test Wazuh severity mapping."""
        handler = WebhookHandler()
        assert handler._map_wazuh_severity(12) == "critical"
        assert handler._map_wazuh_severity(8) == "high"
        assert handler._map_wazuh_severity(4) == "medium"
        assert handler._map_wazuh_severity(1) == "low"


class TestPlaybook:
    """Test playbook."""

    def test_playbook_creation(self):
        """Test playbook creation."""
        playbook = Playbook(
            name="Test Playbook",
            description="Test",
        )
        assert playbook.name == "Test Playbook"
        assert playbook.enabled is True

    def test_step_creation(self):
        """Test step creation."""
        step = PlaybookStep(
            name="Test Step",
            actions=[
                PlaybookAction(
                    name="Test Action",
                    action_type=ActionType.NOTIFY,
                )
            ],
        )
        assert step.name == "Test Step"
        assert len(step.actions) == 1

    def test_action_types(self):
        """Test action types."""
        assert ActionType.BLOCK_IP.value == "block_ip"
        assert ActionType.ISOLATE_HOST.value == "isolate_host"
        assert ActionType.NOTIFY.value == "notify"

    def test_playbook_engine(self):
        """Test playbook engine."""
        engine = PlaybookEngine()
        playbook = Playbook(
            name="Test Playbook",
            steps=[
                PlaybookStep(
                    name="Step 1",
                    actions=[
                        PlaybookAction(
                            name="Action 1",
                            action_type=ActionType.NOTIFY,
                        )
                    ],
                )
            ],
        )
        engine.register_playbook(playbook)
        assert len(engine.list_playbooks()) == 1

    @pytest.mark.asyncio
    async def test_playbook_execution(self):
        """Test playbook execution."""
        engine = PlaybookEngine()
        executed_actions = []

        async def mock_handler(params, context):
            executed_actions.append(params)
            return {"status": "success"}

        engine.register_action_handler(ActionType.NOTIFY, mock_handler)

        playbook = Playbook(
            name="Test Playbook",
            steps=[
                PlaybookStep(
                    name="Step 1",
                    actions=[
                        PlaybookAction(
                            name="Action 1",
                            action_type=ActionType.NOTIFY,
                            parameters={"channel": "#test"},
                        )
                    ],
                )
            ],
        )
        engine.register_playbook(playbook)

        execution = await engine.execute(playbook.id, {"test": "context"})
        assert execution.status.value == "completed"
        assert len(executed_actions) == 1