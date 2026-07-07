"""
Tests for the enhanced playbook engine.
"""

import pytest
import tempfile
import os
import yaml
from datetime import datetime

from cobalto.soar.playbook import (
    Playbook,
    PlaybookAction,
    PlaybookStep,
    PlaybookMetadata,
    PlaybookStatus,
    PlaybookExecution,
    PlaybookVersion,
    PlaybookVersionManager,
    TemplateEngine,
    PlaybookYAMLParser,
    PlaybookEngine,
    ActionType,
    ActionStatus,
)


class TestPlaybookModels:
    """Test playbook data models."""

    def test_playbook_action_creation(self):
        action = PlaybookAction(
            name="Block IP",
            action_type=ActionType.BLOCK_IP,
            parameters={"ip": "192.168.1.1"},
        )
        assert action.name == "Block IP"
        assert action.action_type == ActionType.BLOCK_IP
        assert action.parameters["ip"] == "192.168.1.1"
        assert action.requires_approval is False
        assert action.timeout_seconds == 300

    def test_playbook_action_with_approval(self):
        action = PlaybookAction(
            name="Isolate Host",
            action_type=ActionType.ISOLATE_HOST,
            requires_approval=True,
            approval_timeout_seconds=600,
        )
        assert action.requires_approval is True
        assert action.approval_timeout_seconds == 600

    def test_playbook_step_creation(self):
        step = PlaybookStep(
            name="Response",
            actions=[
                PlaybookAction(name="Block IP", action_type=ActionType.BLOCK_IP),
                PlaybookAction(name="Notify", action_type=ActionType.NOTIFY),
            ],
            parallel=False,
        )
        assert step.name == "Response"
        assert len(step.actions) == 2
        assert step.parallel is False

    def test_playbook_metadata_creation(self):
        metadata = PlaybookMetadata(
            name="Incident Response",
            description="Standard IR playbook",
            version="1.0.0",
            author="SOC Team",
            tags=["incident", "response"],
        )
        assert metadata.name == "Incident Response"
        assert metadata.version == "1.0.0"
        assert metadata.status == PlaybookStatus.DRAFT

    def test_playbook_creation(self):
        playbook = Playbook(
            metadata=PlaybookMetadata(name="Test Playbook"),
            steps=[
                PlaybookStep(
                    name="Step 1",
                    actions=[PlaybookAction(name="Action 1", action_type=ActionType.ENRICH)],
                )
            ],
        )
        assert playbook.metadata.name == "Test Playbook"
        assert len(playbook.steps) == 1

    def test_playbook_get_step(self):
        step = PlaybookStep(id="step-1", name="Step 1")
        playbook = Playbook(
            metadata=PlaybookMetadata(name="Test"),
            steps=[step],
        )
        found = playbook.get_step("step-1")
        assert found is not None
        assert found.name == "Step 1"

    def test_playbook_get_next_step(self):
        step1 = PlaybookStep(id="step-1", name="Step 1")
        step2 = PlaybookStep(id="step-2", name="Step 2")
        playbook = Playbook(
            metadata=PlaybookMetadata(name="Test"),
            steps=[step1, step2],
        )
        next_step = playbook.get_next_step("step-1")
        assert next_step is not None
        assert next_step.name == "Step 2"


class TestTemplateEngine:
    """Test template engine functionality."""

    def test_render_simple_variable(self):
        result = TemplateEngine.render("Hello {{name}}", {"name": "World"})
        assert result == "Hello World"

    def test_render_multiple_variables(self):
        result = TemplateEngine.render(
            "{{greeting}} {{name}}!",
            {"greeting": "Hello", "name": "World"},
        )
        assert result == "Hello World!"

    def test_render_nested_variable(self):
        result = TemplateEngine.render(
            "Source IP: {{alert.src_ip}}",
            {"alert": {"src_ip": "192.168.1.1"}},
        )
        assert result == "Source IP: 192.168.1.1"

    def test_render_missing_variable(self):
        result = TemplateEngine.render("Hello {{name}}", {})
        assert result == "Hello {{name}}"

    def test_render_dict(self):
        data = {"ip": "{{source_ip}}", "action": "block"}
        context = {"source_ip": "10.0.0.1"}
        result = TemplateEngine.render_dict(data, context)
        assert result["ip"] == "10.0.0.1"
        assert result["action"] == "block"

    def test_render_nested_dict(self):
        data = {"params": {"ip": "{{src_ip}}", "port": "{{src_port}}"}}
        context = {"src_ip": "10.0.0.1", "src_port": 443}
        result = TemplateEngine.render_dict(data, context)
        assert result["params"]["ip"] == "10.0.0.1"
        assert result["params"]["port"] == "443"  # Templates render as strings

    def test_render_list(self):
        data = ["{{item1}}", "{{item2}}", "static"]
        context = {"item1": "a", "item2": "b"}
        result = TemplateEngine.render_dict({"items": data}, context)
        assert result["items"] == ["a", "b", "static"]

    def test_extract_variables(self):
        variables = TemplateEngine.extract_variables(
            "{{greeting}} {{name}}, your IP is {{ip}}"
        )
        assert set(variables) == {"greeting", "name", "ip"}

    def test_validate_template_valid(self):
        template = "{{name}} has severity {{level}}"
        context = {"name": "test", "level": "high"}
        valid, missing = TemplateEngine.validate_template(template, context)
        assert valid is True
        assert missing == []

    def test_validate_template_missing(self):
        template = "{{name}} has severity {{level}}"
        context = {"name": "test"}
        valid, missing = TemplateEngine.validate_template(template, context)
        assert valid is False
        assert "level" in missing


class TestPlaybookVersionManager:
    """Test playbook version management."""

    def test_save_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PlaybookVersionManager(storage_path=tmpdir)
            playbook = Playbook(
                metadata=PlaybookMetadata(
                    name="Test",
                    version="1.0.0",
                ),
            )
            version = manager.save_version(playbook, created_by="test", changes="Initial")
            assert version.version == "1.0.0"
            assert version.changes == "Initial"

    def test_get_versions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PlaybookVersionManager(storage_path=tmpdir)
            playbook = Playbook(
                metadata=PlaybookMetadata(id="test-1", name="Test", version="1.0.0"),
            )
            manager.save_version(playbook)
            versions = manager.get_versions("test-1")
            assert len(versions) == 1

    def test_get_latest_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PlaybookVersionManager(storage_path=tmpdir)
            playbook = Playbook(
                metadata=PlaybookMetadata(id="test-1", name="Test", version="1.0.0"),
            )
            manager.save_version(playbook)
            latest = manager.get_latest_version("test-1")
            assert latest is not None
            assert latest.version == "1.0.0"

    def test_calculate_checksum(self):
        manager = PlaybookVersionManager()
        playbook = Playbook(
            metadata=PlaybookMetadata(name="Test", version="1.0.0"),
        )
        checksum1 = manager.calculate_checksum(playbook)
        checksum2 = manager.calculate_checksum(playbook)
        assert checksum1 == checksum2
        assert len(checksum1) == 16

    def test_revert_to_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PlaybookVersionManager(storage_path=tmpdir)
            playbook = Playbook(
                metadata=PlaybookMetadata(id="test-1", name="Test", version="1.0.0"),
                steps=[
                    PlaybookStep(
                        name="Step 1",
                        actions=[PlaybookAction(name="Action 1", action_type=ActionType.ENRICH)],
                    )
                ],
            )
            manager.save_version(playbook)
            reverted = manager.revert_to_version("test-1", "1.0.0")
            assert reverted is not None
            assert len(reverted.steps) == 1


class TestPlaybookYAMLParser:
    """Test YAML parser functionality."""

    def test_parse_yaml(self):
        yaml_content = """
metadata:
  name: Test Playbook
  version: "1.0.0"
  description: A test playbook
  tags:
    - test
    - security
steps:
  - name: Triage
    description: Initial triage
    actions:
      - name: Parse Alert
        action_type: enrich
        parameters:
          type: parse_alert
  - name: Response
    parallel: false
    actions:
      - name: Block IP
        action_type: block_ip
        parameters:
          ip: "{{source_ip}}"
        requires_approval: true
variables:
  threshold: 7
"""
        playbook = PlaybookYAMLParser.from_yaml(yaml_content)
        assert playbook.metadata.name == "Test Playbook"
        assert playbook.metadata.version == "1.0.0"
        assert len(playbook.steps) == 2
        assert playbook.variables["threshold"] == 7

    def test_to_yaml(self):
        playbook = Playbook(
            metadata=PlaybookMetadata(
                name="YAML Test",
                version="1.0.0",
            ),
            steps=[
                PlaybookStep(
                    name="Step 1",
                    actions=[
                        PlaybookAction(name="Action 1", action_type=ActionType.ENRICH)
                    ],
                )
            ],
        )
        yaml_output = PlaybookYAMLParser.to_yaml(playbook)
        assert "YAML Test" in yaml_output
        assert "step_1" in yaml_output or "Step 1" in yaml_output

    def test_parse_yaml_with_conditions(self):
        yaml_content = """
metadata:
  name: Conditional Playbook
  version: "1.0.0"
steps:
  - name: Check Severity
    condition: "severity >= 8"
    actions:
      - name: Escalate
        action_type: escalate
        parameters:
          reason: High severity alert
"""
        playbook = PlaybookYAMLParser.from_yaml(yaml_content)
        assert playbook.steps[0].condition == "severity >= 8"


class TestPlaybookEngine:
    """Test enhanced playbook engine."""

    def test_engine_initialization(self):
        engine = PlaybookEngine()
        assert engine._action_handlers == {}
        assert engine._playbooks == {}

    def test_register_playbook(self):
        engine = PlaybookEngine()
        playbook = Playbook(
            metadata=PlaybookMetadata(name="Test", version="1.0.0"),
        )
        version = engine.register_playbook(playbook)
        assert version.version == "1.0.0"

    def test_list_playbooks(self):
        engine = PlaybookEngine()
        playbook = Playbook(
            metadata=PlaybookMetadata(
                id="test-1",
                name="Test Playbook",
                version="1.0.0",
            ),
        )
        engine.register_playbook(playbook)
        playbooks = engine.list_playbooks()
        assert len(playbooks) == 1
        assert playbooks[0]["name"] == "Test Playbook"

    def test_evaluate_condition(self):
        engine = PlaybookEngine()
        context = {"severity": 8, "source": "wazuh"}

        assert engine._evaluate_condition("severity > 7", context) is True
        assert engine._evaluate_condition("severity < 7", context) is False
        assert engine._evaluate_condition("severity == 8", context) is True
        assert engine._evaluate_condition("severity >= 8", context) is True
        assert engine._evaluate_condition("source == wazuh", context) is True
        assert engine._evaluate_condition("source != siem", context) is True

    @pytest.mark.asyncio
    async def test_execute_playbook(self):
        engine = PlaybookEngine()

        # Register mock handler
        async def mock_handler(params, context):
            return {"status": "success", "ip": params.get("ip")}

        engine.register_action_handler(ActionType.BLOCK_IP, mock_handler)

        # Create playbook
        playbook = Playbook(
            metadata=PlaybookMetadata(id="test-1", name="Test", version="1.0.0"),
            steps=[
                PlaybookStep(
                    name="Block",
                    actions=[
                        PlaybookAction(
                            name="Block IP",
                            action_type=ActionType.BLOCK_IP,
                            parameters={"ip": "{{source_ip}}"},
                        )
                    ],
                )
            ],
        )
        engine.register_playbook(playbook)

        # Execute
        execution = await engine.execute(
            "test-1",
            {"source_ip": "192.168.1.1"},
        )

        assert execution.status == PlaybookStatus.ACTIVE
        assert execution.completed_at is not None
        assert len(execution.action_results) == 1

    @pytest.mark.asyncio
    async def test_execute_with_conditions(self):
        engine = PlaybookEngine()

        async def mock_handler(params, context):
            return {"executed": True}

        engine.register_action_handler(ActionType.ESCALATE, mock_handler)

        playbook = Playbook(
            metadata=PlaybookMetadata(id="test-1", name="Test", version="1.0.0"),
            steps=[
                PlaybookStep(
                    name="Conditional Step",
                    condition="severity >= 8",
                    actions=[
                        PlaybookAction(
                            name="Escalate",
                            action_type=ActionType.ESCALATE,
                        )
                    ],
                )
            ],
        )
        engine.register_playbook(playbook)

        # Execute with high severity (should run)
        execution = await engine.execute("test-1", {"severity": 9})
        assert len(execution.action_results) == 1

        # Execute with low severity (should skip)
        execution2 = await engine.execute("test-1", {"severity": 3})
        assert len(execution2.action_results) == 0


class TestPlaybookIntegration:
    """Integration tests for playbook system."""

    def test_full_yaml_roundtrip(self):
        yaml_content = """
metadata:
  name: Incident Response
  version: "1.0.0"
  description: Standard IR playbook
  author: SOC Team
  tags:
    - incident
    - response
  triggers:
    - "severity >= 8"
steps:
  - name: Triage
    description: Initial triage
    actions:
      - name: Parse Alert
        action_type: enrich
        parameters:
          type: parse_alert
      - name: Check IOCs
        action_type: enrich
        parameters:
          type: ioc_check
  - name: Investigation
    parallel: true
    actions:
      - name: Enrich Source IP
        action_type: enrich
        parameters:
          type: ip_enrichment
          ip: "{{source_ip}}"
      - name: Query Threat Intel
        action_type: query
        parameters:
          type: threat_intel
          indicators: "{{indicators}}"
  - name: Response
    actions:
      - name: Block Malicious IP
        action_type: block_ip
        parameters:
          ip: "{{source_ip}}"
          reason: "{{rule_description}}"
        requires_approval: true
        approval_timeout_seconds: 300
variables:
  auto_block_threshold: 8
  notify_channel: "#soc-alerts"
"""
        # Parse
        playbook = PlaybookYAMLParser.from_yaml(yaml_content)

        # Verify
        assert playbook.metadata.name == "Incident Response"
        assert len(playbook.steps) == 3
        assert playbook.steps[1].parallel is True
        assert playbook.variables["auto_block_threshold"] == 8

        # Serialize back
        yaml_output = PlaybookYAMLParser.to_yaml(playbook)
        assert "Incident Response" in yaml_output
        assert "block_ip" in yaml_output

    def test_version_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = PlaybookEngine()
            engine._version_manager = PlaybookVersionManager(storage_path=tmpdir)

            # Create playbook
            playbook = Playbook(
                metadata=PlaybookMetadata(id="ir-1", name="IR Playbook", version="1.0.0"),
                steps=[
                    PlaybookStep(
                        name="Step 1",
                        actions=[PlaybookAction(name="Action 1", action_type=ActionType.ENRICH)],
                    )
                ],
            )
            v1 = engine.register_playbook(playbook)
            assert v1.version == "1.0.0"

            # Update version
            playbook.metadata.version = "1.1.0"
            playbook.steps[0].actions.append(
                PlaybookAction(name="Action 2", action_type=ActionType.NOTIFY)
            )
            v2 = engine.get_version_manager().save_version(
                playbook, changes="Added notification action"
            )
            assert v2.version == "1.1.0"

            # Check history
            versions = engine.get_version_manager().get_versions("ir-1")
            assert len(versions) == 2

            # Compare
            comparison = engine.get_version_manager().compare_versions("ir-1", "1.0.0", "1.1.0")
            assert comparison["checksum_match"] is False
