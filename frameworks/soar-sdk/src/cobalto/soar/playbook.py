"""
Enhanced Playbook Engine with YAML DSL, Version Manager, and Template Engine.

Supports:
- YAML-based playbook definitions
- Version tracking with history
- Template variable substitution ({{variable}})
- Conditional execution
- Parallel and sequential actions
- Approval gates
"""

import os
import yaml
import hashlib
import copy
from typing import Any, Dict, List, Optional, Callable, Tuple
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
import uuid
import re
import json


class ActionType(str, Enum):
    """Supported action types."""
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    QUARANTINE_FILE = "quarantine_file"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY = "notify"
    ESCALATE = "escalate"
    ENRICH = "enrich"
    QUERY = "query"
    WAIT = "wait"
    CONDITION = "condition"
    CUSTOM = "custom"
    WEBHOOK = "webhook"
    LOG = "log"


class ActionStatus(str, Enum):
    """Action execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"
    CANCELLED = "cancelled"


class PlaybookAction(BaseModel):
    """A single action in a playbook."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    action_type: ActionType
    parameters: Dict[str, Any] = {}
    timeout_seconds: int = 300
    retry_count: int = 0
    retry_delay_seconds: float = 1.0
    requires_approval: bool = False
    approval_timeout_seconds: int = 600
    on_success: Optional[str] = None
    on_failure: Optional[str] = None
    condition: Optional[str] = None
    metadata: Dict[str, Any] = {}


class PlaybookStep(BaseModel):
    """A step in a playbook containing one or more actions."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    actions: List[PlaybookAction] = []
    parallel: bool = False
    condition: Optional[str] = None
    next_step: Optional[str] = None


class PlaybookStatus(str, Enum):
    """Playbook lifecycle status."""
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class PlaybookMetadata(BaseModel):
    """Playbook metadata for versioning."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    tags: List[str] = []
    triggers: List[str] = []
    enabled: bool = True
    status: PlaybookStatus = PlaybookStatus.DRAFT
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = ""
    updated_by: str = ""
    checksum: str = ""
    min_cobalto_version: str = "0.1.0"
    references: List[str] = []


class Playbook(BaseModel):
    """A complete playbook definition."""
    metadata: PlaybookMetadata
    steps: List[PlaybookStep] = []
    variables: Dict[str, Any] = {}
    secrets: List[str] = []

    def get_step(self, step_id: str) -> Optional[PlaybookStep]:
        """Get a step by ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def get_next_step(self, current_step_id: str) -> Optional[PlaybookStep]:
        """Get the next step after the current one."""
        for i, step in enumerate(self.steps):
            if step.id == current_step_id:
                if i + 1 < len(self.steps):
                    return self.steps[i + 1]
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert playbook to dictionary."""
        return {
            "metadata": self.metadata.model_dump(),
            "steps": [step.model_dump() for step in self.steps],
            "variables": self.variables,
            "secrets": self.secrets,
        }


class PlaybookExecution(BaseModel):
    """Execution state of a playbook."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str
    playbook_version: str = "1.0.0"
    status: PlaybookStatus = PlaybookStatus.DRAFT
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step: Optional[str] = None
    action_results: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    context: Dict[str, Any] = {}
    triggered_by: str = ""
    trigger_event: Dict[str, Any] = {}


class PlaybookVersion(BaseModel):
    """Version history entry."""
    version: str
    checksum: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = ""
    changes: str = ""
    playbook_snapshot: Dict[str, Any] = {}


class PlaybookVersionManager:
    """Manages playbook versions and history."""

    def __init__(self, storage_path: str = ".playbook_versions"):
        self._storage_path = storage_path
        self._versions: Dict[str, List[PlaybookVersion]] = {}

    def _ensure_storage(self) -> None:
        """Ensure storage directory exists."""
        os.makedirs(self._storage_path, exist_ok=True)

    def _get_playbook_path(self, playbook_id: str) -> str:
        """Get storage path for a playbook."""
        return os.path.join(self._storage_path, f"{playbook_id}.json")

    def calculate_checksum(self, playbook: Playbook) -> str:
        """Calculate checksum for playbook content."""
        content = json.dumps(playbook.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def save_version(
        self,
        playbook: Playbook,
        created_by: str = "",
        changes: str = "",
    ) -> PlaybookVersion:
        """Save a new version of a playbook."""
        self._ensure_storage()

        version_entry = PlaybookVersion(
            version=playbook.metadata.version,
            checksum=self.calculate_checksum(playbook),
            created_by=created_by,
            changes=changes,
            playbook_snapshot=playbook.to_dict(),
        )

        if playbook.metadata.id not in self._versions:
            self._versions[playbook.metadata.id] = []

        self._versions[playbook.metadata.id].append(version_entry)

        # Persist to disk
        versions_data = [v.model_dump() for v in self._versions[playbook.metadata.id]]
        with open(self._get_playbook_path(playbook.metadata.id), "w") as f:
            json.dump(versions_data, f, indent=2, default=str)

        return version_entry

    def get_versions(self, playbook_id: str) -> List[PlaybookVersion]:
        """Get all versions of a playbook."""
        if playbook_id not in self._versions:
            # Try to load from disk
            path = self._get_playbook_path(playbook_id)
            if os.path.exists(path):
                with open(path, "r") as f:
                    data = json.load(f)
                self._versions[playbook_id] = [PlaybookVersion(**v) for v in data]
            else:
                return []
        return self._versions[playbook_id]

    def get_version(self, playbook_id: str, version: str) -> Optional[PlaybookVersion]:
        """Get a specific version of a playbook."""
        versions = self.get_versions(playbook_id)
        for v in versions:
            if v.version == version:
                return v
        return None

    def get_latest_version(self, playbook_id: str) -> Optional[PlaybookVersion]:
        """Get the latest version of a playbook."""
        versions = self.get_versions(playbook_id)
        return versions[-1] if versions else None

    def revert_to_version(
        self,
        playbook_id: str,
        version: str,
    ) -> Optional[Playbook]:
        """Revert to a specific version."""
        version_entry = self.get_version(playbook_id, version)
        if not version_entry:
            return None
        return Playbook(**version_entry.playbook_snapshot)

    def compare_versions(
        self,
        playbook_id: str,
        version1: str,
        version2: str,
    ) -> Dict[str, Any]:
        """Compare two versions of a playbook."""
        v1 = self.get_version(playbook_id, version1)
        v2 = self.get_version(playbook_id, version2)

        if not v1 or not v2:
            return {"error": "Version not found"}

        return {
            "version1": version1,
            "version2": version2,
            "checksum_match": v1.checksum == v2.checksum,
            "v1_created": v1.created_at.isoformat(),
            "v2_created": v2.created_at.isoformat(),
            "v1_changes": v1.changes,
            "v2_changes": v2.changes,
        }


class TemplateEngine:
    """Template engine for variable substitution in playbooks."""

    VARIABLE_PATTERN = re.compile(r"\{\{(\w+(?:\.\w+)*)\}\}")

    @staticmethod
    def render(template: str, context: Dict[str, Any]) -> str:
        """Render a template string with context variables."""
        def replace_var(match):
            var_path = match.group(1)
            value = TemplateEngine._resolve_variable(var_path, context)
            return str(value) if value is not None else match.group(0)

        return TemplateEngine.VARIABLE_PATTERN.sub(replace_var, template)

    @staticmethod
    def _resolve_variable(var_path: str, context: Dict[str, Any]) -> Any:
        """Resolve a dot-notation variable path."""
        parts = var_path.split(".")
        current = context

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None

        return current

    @staticmethod
    def render_dict(data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Render all string values in a dictionary."""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = TemplateEngine.render(value, context)
            elif isinstance(value, dict):
                result[key] = TemplateEngine.render_dict(value, context)
            elif isinstance(value, list):
                result[key] = [
                    TemplateEngine.render(item, context) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    @staticmethod
    def extract_variables(template: str) -> List[str]:
        """Extract all variable names from a template."""
        return list(set(TemplateEngine.VARIABLE_PATTERN.findall(template)))

    @staticmethod
    def validate_template(template: str, available_vars: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate that all template variables are available."""
        required_vars = TemplateEngine.extract_variables(template)
        missing = [v for v in required_vars if v not in available_vars]
        return len(missing) == 0, missing


class PlaybookYAMLParser:
    """Parser for YAML-based playbook definitions."""

    @staticmethod
    def from_yaml(yaml_content: str) -> Playbook:
        """Parse a playbook from YAML content."""
        data = yaml.safe_load(yaml_content)
        return PlaybookYAMLParser._parse_playbook(data)

    @staticmethod
    def from_yaml_file(file_path: str) -> Playbook:
        """Load a playbook from a YAML file."""
        with open(file_path, "r") as f:
            return PlaybookYAMLParser.from_yaml(f.read())

    @staticmethod
    def to_yaml(playbook: Playbook) -> str:
        """Serialize a playbook to YAML."""
        data = playbook.to_dict()
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    @staticmethod
    def _parse_playbook(data: Dict[str, Any]) -> Playbook:
        """Parse playbook from dict."""
        metadata_data = data.get("metadata", {})
        metadata = PlaybookMetadata(
            id=metadata_data.get("id", str(uuid.uuid4())),
            name=metadata_data.get("name", "Unnamed Playbook"),
            description=metadata_data.get("description", ""),
            version=metadata_data.get("version", "1.0.0"),
            author=metadata_data.get("author", ""),
            tags=metadata_data.get("tags", []),
            triggers=metadata_data.get("triggers", []),
            enabled=metadata_data.get("enabled", True),
            status=PlaybookStatus(metadata_data.get("status", "draft")),
            created_by=metadata_data.get("created_by", ""),
            updated_by=metadata_data.get("updated_by", ""),
            min_cobalto_version=metadata_data.get("min_cobalto_version", "0.1.0"),
            references=metadata_data.get("references", []),
        )

        steps = [PlaybookYAMLParser._parse_step(step) for step in data.get("steps", [])]

        return Playbook(
            metadata=metadata,
            steps=steps,
            variables=data.get("variables", {}),
            secrets=data.get("secrets", []),
        )

    @staticmethod
    def _parse_step(data: Dict[str, Any]) -> PlaybookStep:
        """Parse a step from dict."""
        return PlaybookStep(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", "Unnamed Step"),
            description=data.get("description", ""),
            actions=[PlaybookYAMLParser._parse_action(a) for a in data.get("actions", [])],
            parallel=data.get("parallel", False),
            condition=data.get("condition"),
            next_step=data.get("next_step"),
        )

    @staticmethod
    def _parse_action(data: Dict[str, Any]) -> PlaybookAction:
        """Parse an action from dict."""
        return PlaybookAction(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", "Unnamed Action"),
            action_type=ActionType(data.get("action_type", "custom")),
            parameters=data.get("parameters", {}),
            timeout_seconds=data.get("timeout_seconds", 300),
            retry_count=data.get("retry_count", 0),
            retry_delay_seconds=data.get("retry_delay_seconds", 1.0),
            requires_approval=data.get("requires_approval", False),
            approval_timeout_seconds=data.get("approval_timeout_seconds", 600),
            on_success=data.get("on_success"),
            on_failure=data.get("on_failure"),
            condition=data.get("condition"),
            metadata=data.get("metadata", {}),
        )


class PlaybookEngine:
    """Enhanced engine for executing playbooks with template support."""

    def __init__(self):
        self._action_handlers: Dict[ActionType, Callable] = {}
        self._condition_evaluators: Dict[str, Callable] = {}
        self._playbooks: Dict[str, Playbook] = {}
        self._executions: Dict[str, PlaybookExecution] = {}
        self._version_manager = PlaybookVersionManager()
        self._template_engine = TemplateEngine()

    def register_action_handler(
        self,
        action_type: ActionType,
        handler: Callable,
    ) -> None:
        """Register a handler for an action type."""
        self._action_handlers[action_type] = handler

    def register_condition_evaluator(
        self,
        condition_name: str,
        evaluator: Callable,
    ) -> None:
        """Register a condition evaluator."""
        self._condition_evaluators[condition_name] = evaluator

    def register_playbook(self, playbook: Playbook) -> PlaybookVersion:
        """Register a playbook and save initial version."""
        self._playbooks[playbook.metadata.id] = playbook
        return self._version_manager.save_version(playbook, changes="Initial version")

    def load_playbook_from_yaml(self, yaml_path: str) -> Playbook:
        """Load a playbook from a YAML file."""
        playbook = PlaybookYAMLParser.from_yaml_file(yaml_path)
        self.register_playbook(playbook)
        return playbook

    def load_playbooks_from_directory(self, directory: str) -> List[Playbook]:
        """Load all playbooks from a directory."""
        playbooks = []
        for filename in os.listdir(directory):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(directory, filename)
                try:
                    playbook = self.load_playbook_from_yaml(filepath)
                    playbooks.append(playbook)
                except Exception as e:
                    print(f"Error loading playbook {filename}: {e}")
        return playbooks

    def save_playbook_to_yaml(self, playbook: Playbook, yaml_path: str) -> None:
        """Save a playbook to a YAML file."""
        yaml_content = PlaybookYAMLParser.to_yaml(playbook)
        with open(yaml_path, "w") as f:
            f.write(yaml_content)

    def get_version_manager(self) -> PlaybookVersionManager:
        """Get the version manager instance."""
        return self._version_manager

    async def execute(
        self,
        playbook_id: str,
        context: Dict[str, Any],
        triggered_by: str = "",
    ) -> PlaybookExecution:
        """Execute a playbook with template rendering."""
        playbook = self._playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")

        execution = PlaybookExecution(
            playbook_id=playbook_id,
            playbook_version=playbook.metadata.version,
            status=PlaybookStatus.ACTIVE,
            started_at=datetime.utcnow(),
            context=context,
            triggered_by=triggered_by,
        )
        self._executions[execution.id] = execution

        try:
            # Merge playbook variables with execution context
            merged_context = {**playbook.variables, **context}

            for step in playbook.steps:
                execution.current_step = step.id

                # Check step condition
                if step.condition:
                    rendered_condition = self._template_engine.render(
                        step.condition, merged_context
                    )
                    if not self._evaluate_condition(rendered_condition, merged_context):
                        continue

                # Execute actions
                if step.parallel:
                    import asyncio
                    tasks = [
                        self._execute_action(action, execution, merged_context)
                        for action in step.actions
                    ]
                    await asyncio.gather(*tasks)
                else:
                    for action in step.actions:
                        await self._execute_action(action, execution, merged_context)

            execution.status = PlaybookStatus.ACTIVE
            execution.completed_at = datetime.utcnow()

        except Exception as e:
            execution.status = PlaybookStatus.FAILED
            execution.errors.append(str(e))
            execution.completed_at = datetime.utcnow()

        return execution

    async def _execute_action(
        self,
        action: PlaybookAction,
        execution: PlaybookExecution,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a single action with template rendering."""
        handler = self._action_handlers.get(action.action_type)
        if not handler:
            raise ValueError(f"No handler for action type {action.action_type}")

        # Check action condition
        if action.condition:
            rendered_condition = self._template_engine.render(action.condition, context)
            if not self._evaluate_condition(rendered_condition, context):
                execution.action_results[action.id] = {
                    "status": ActionStatus.SKIPPED.value,
                    "reason": "condition_not_met",
                }
                return {"skipped": True}

        # Render parameters
        rendered_params = self._template_engine.render_dict(action.parameters, context)

        execution.action_results[action.id] = {
            "status": ActionStatus.RUNNING.value,
            "started_at": datetime.utcnow().isoformat(),
        }

        try:
            result = await handler(rendered_params, context)
            execution.action_results[action.id] = {
                "status": ActionStatus.COMPLETED.value,
                "result": result,
                "completed_at": datetime.utcnow().isoformat(),
            }
            return result
        except Exception as e:
            execution.action_results[action.id] = {
                "status": ActionStatus.FAILED.value,
                "error": str(e),
                "completed_at": datetime.utcnow().isoformat(),
            }
            raise

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate a condition string."""
        evaluator = self._condition_evaluators.get(condition)
        if evaluator:
            return evaluator(context)

        # Simple condition evaluation
        try:
            parts = condition.split()
            if len(parts) == 3:
                field, op, value = parts
                context_value = TemplateEngine._resolve_variable(field, context)
                if context_value is None:
                    return False

                value_clean = value.strip("'\"")

                if op == "==":
                    return str(context_value) == value_clean
                elif op == "!=":
                    return str(context_value) != value_clean
                elif op == ">":
                    return float(context_value) > float(value_clean)
                elif op == "<":
                    return float(context_value) < float(value_clean)
                elif op == ">=":
                    return float(context_value) >= float(value_clean)
                elif op == "<=":
                    return float(context_value) <= float(value_clean)
                elif op == "contains":
                    return value_clean in str(context_value)
                elif op == "not_contains":
                    return value_clean not in str(context_value)
            return False
        except Exception:
            return False

    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        """Get an execution by ID."""
        return self._executions.get(execution_id)

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all registered playbooks."""
        return [
            {
                "id": p.metadata.id,
                "name": p.metadata.name,
                "description": p.metadata.description,
                "version": p.metadata.version,
                "enabled": p.metadata.enabled,
                "status": p.metadata.status.value,
                "steps_count": len(p.steps),
            }
            for p in self._playbooks.values()
        ]

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID."""
        return self._playbooks.get(playbook_id)
