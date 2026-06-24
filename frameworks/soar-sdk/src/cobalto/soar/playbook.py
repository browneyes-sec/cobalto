"""
Playbook definitions for automated response workflows.
Defines step-by-step actions for security incident response.
"""

from typing import Any, Dict, List, Optional, Callable
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
import json
import uuid


class ActionType(str, Enum):
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


class ActionStatus(str, Enum):
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
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class PlaybookExecution(BaseModel):
    """Execution state of a playbook."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str
    status: PlaybookStatus = PlaybookStatus.DRAFT
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step: Optional[str] = None
    action_results: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    context: Dict[str, Any] = {}


class Playbook(BaseModel):
    """A playbook definition."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    version: str = "1.0.0"
    steps: List[PlaybookStep] = []
    triggers: List[str] = []
    tags: List[str] = []
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}

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
        return self.model_dump()


class PlaybookEngine:
    """Engine for executing playbooks."""

    def __init__(self):
        self._action_handlers: Dict[ActionType, Callable] = {}
        self._condition_evaluators: Dict[str, Callable] = {}
        self._playbooks: Dict[str, Playbook] = {}
        self._executions: Dict[str, PlaybookExecution] = {}

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

    def register_playbook(self, playbook: Playbook) -> None:
        """Register a playbook."""
        self._playbooks[playbook.id] = playbook

    async def execute(
        self,
        playbook_id: str,
        context: Dict[str, Any],
    ) -> PlaybookExecution:
        """Execute a playbook."""
        playbook = self._playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")

        execution = PlaybookExecution(
            playbook_id=playbook_id,
            status=PlaybookStatus.ACTIVE,
            started_at=datetime.utcnow(),
            context=context,
        )
        self._executions[execution.id] = execution

        try:
            for step in playbook.steps:
                execution.current_step = step.id

                # Check step condition
                if step.condition:
                    if not self._evaluate_condition(step.condition, execution.context):
                        continue

                # Execute actions
                if step.parallel:
                    # Execute actions in parallel
                    import asyncio
                    tasks = [
                        self._execute_action(action, execution)
                        for action in step.actions
                    ]
                    await asyncio.gather(*tasks)
                else:
                    # Execute actions sequentially
                    for action in step.actions:
                        await self._execute_action(action, execution)

            execution.status = PlaybookStatus.COMPLETED
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
    ) -> Dict[str, Any]:
        """Execute a single action."""
        handler = self._action_handlers.get(action.action_type)
        if not handler:
            raise ValueError(f"No handler for action type {action.action_type}")

        execution.action_results[action.id] = {
            "status": ActionStatus.RUNNING.value,
            "started_at": datetime.utcnow().isoformat(),
        }

        try:
            result = await handler(action.parameters, execution.context)
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
        """Evaluate a condition."""
        evaluator = self._condition_evaluators.get(condition)
        if evaluator:
            return evaluator(context)

        # Simple condition evaluation
        try:
            # Example: "severity == 'critical'"
            parts = condition.split()
            if len(parts) == 3:
                field, op, value = parts
                context_value = context.get(field)
                if op == "==":
                    return str(context_value) == value.strip("'\"")
                elif op == "!=":
                    return str(context_value) != value.strip("'\"")
                elif op == ">":
                    return float(context_value) > float(value)
                elif op == "<":
                    return float(context_value) < float(value)
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
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "enabled": p.enabled,
                "steps_count": len(p.steps),
            }
            for p in self._playbooks.values()
        ]


# Pre-defined playbooks
INCIDENT_RESPONSE_PLAYBOOK = Playbook(
    name="Incident Response",
    description="Standard incident response playbook",
    triggers=["alert.severity >= 8"],
    tags=["incident", "response", "standard"],
    steps=[
        PlaybookStep(
            name="Triage",
            description="Initial triage of the alert",
            actions=[
                PlaybookAction(
                    name="Parse Alert",
                    action_type=ActionType.ENRICH,
                    parameters={"type": "parse_alert"},
                ),
                PlaybookAction(
                    name="Check IOCs",
                    action_type=ActionType.ENRICH,
                    parameters={"type": "ioc_check"},
                ),
            ],
        ),
        PlaybookStep(
            name="Investigation",
            description="Deep investigation of the incident",
            actions=[
                PlaybookAction(
                    name="Enrich Source IP",
                    action_type=ActionType.ENRICH,
                    parameters={"type": "ip_enrichment"},
                ),
                PlaybookAction(
                    name="Query Threat Intel",
                    action_type=ActionType.QUERY,
                    parameters={"type": "threat_intel"},
                ),
            ],
            parallel=True,
        ),
        PlaybookStep(
            name="Response",
            description="Execute response actions",
            actions=[
                PlaybookAction(
                    name="Block Malicious IP",
                    action_type=ActionType.BLOCK_IP,
                    parameters={"ip": "{{source_ip}}"},
                    requires_approval=True,
                ),
                PlaybookAction(
                    name="Isolate Host",
                    action_type=ActionType.ISOLATE_HOST,
                    parameters={"host": "{{host_name}}"},
                    requires_approval=True,
                ),
            ],
        ),
        PlaybookStep(
            name="Documentation",
            description="Document the incident",
            actions=[
                PlaybookAction(
                    name="Create Case",
                    action_type=ActionType.CUSTOM,
                    parameters={"type": "create_case"},
                ),
                PlaybookAction(
                    name="Notify Analyst",
                    action_type=ActionType.NOTIFY,
                    parameters={"channel": "#soc-alerts"},
                ),
            ],
        ),
    ],
)


def get_default_playbooks() -> List[Playbook]:
    """Get default playbooks."""
    return [INCIDENT_RESPONSE_PLAYBOOK]