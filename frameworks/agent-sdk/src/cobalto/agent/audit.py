"""
Audit Service

Immutable audit trail with HMAC-sealed logs for all agent actions.
Provides tamper-evident logging for compliance and governance.

DTP 3.3: Data Product - agent-runs
DTP 7.2: Action audit trail (immutable log)
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import hashlib
import hmac
import json
import uuid
import boto3
import redis.asyncio as redis
import structlog

logger = structlog.get_logger(__name__)


class AuditEventType(str, Enum):
    AGENT_RUN_STARTED = "agent_run_started"
    AGENT_RUN_COMPLETED = "agent_run_completed"
    AGENT_RUN_FAILED = "agent_run_failed"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    ACTION_EXECUTED = "action_executed"
    ACTION_FAILED = "action_failed"
    CONTEXT_BUILT = "context_built"
    ALERT_INGESTED = "alert_ingested"


class AuditEvent(BaseModel):
    """Immutable audit event."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    incident_id: str
    alert_id: Optional[str] = None
    agent_type: Optional[str] = None
    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    status: str = "success"
    details: Dict[str, Any] = {}
    previous_hash: Optional[str] = None
    hmac_signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "agent_type": self.agent_type,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "hmac_signature": self.hmac_signature,
        }


class AuditService:
    """
    Audit service with HMAC-sealed immutable logs.

    Features:
    - Chain of custody via hash linking
    - HMAC signature for tamper detection
    - S3 archival for long-term retention
    - Redis for hot storage and queries
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        hmac_secret: str = "audit-secret-change-in-production",
        s3_bucket: Optional[str] = None,
        s3_prefix: str = "audit-logs",
        enable_s3: bool = False,
    ):
        self.redis_url = redis_url
        self.hmac_secret = hmac_secret
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix
        self.enable_s3 = enable_s3
        self._redis: Optional[redis.Redis] = None
        self._s3_client = None

    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(self.redis_url)
        return self._redis

    def _get_s3_client(self):
        """Get or create S3 client."""
        if self._s3_client is None and self.enable_s3:
            self._s3_client = boto3.client("s3")
        return self._s3_client

    async def log_event(
        self,
        event_type: AuditEventType,
        incident_id: str,
        **kwargs,
    ) -> AuditEvent:
        """Log an audit event."""
        # Get previous hash for chain
        previous_hash = await self._get_last_hash(incident_id)

        # Create event
        event = AuditEvent(
            event_type=event_type,
            incident_id=incident_id,
            previous_hash=previous_hash,
            **kwargs,
        )

        # Generate HMAC signature
        event.hmac_signature = self._sign_event(event)

        # Store in Redis
        r = await self._get_redis()
        event_key = f"audit:{incident_id}:{event.event_id}"
        await r.setex(
            event_key,
            90 * 24 * 3600,  # 90 days TTL
            json.dumps(event.to_dict()),
        )

        # Add to incident index
        await r.lpush(f"audit:index:{incident_id}", event.event_id)

        # Update last hash
        await r.set(f"audit:last_hash:{incident_id}", event.hmac_signature)

        # Archive to S3 if enabled
        if self.enable_s3:
            await self._archive_to_s3(event)

        logger.info(
            "audit_event_logged",
            event_id=event.event_id,
            event_type=event_type.value,
            incident_id=incident_id,
        )

        return event

    async def _get_last_hash(self, incident_id: str) -> Optional[str]:
        """Get the last hash for chain linking."""
        r = await self._get_redis()
        return await r.get(f"audit:last_hash:{incident_id}")

    def _sign_event(self, event: AuditEvent) -> str:
        """Generate HMAC signature for event."""
        # Create canonical representation
        canonical = json.dumps(event.to_dict(), sort_keys=True, default=str)
        return hmac.new(
            self.hmac_secret.encode(),
            canonical.encode(),
            hashlib.sha256,
        ).hexdigest()

    async def _archive_to_s3(self, event: AuditEvent) -> None:
        """Archive event to S3."""
        try:
            s3 = self._get_s3_client()
            if not s3:
                return

            # Organize by date
            date_prefix = event.timestamp.strftime("%Y/%m/%d")
            key = f"{self.s3_prefix}/{date_prefix}/{event.event_id}.json"

            s3.put_object(
                Bucket=self.s3_bucket,
                Key=key,
                Body=json.dumps(event.to_dict(), default=str),
                ContentType="application/json",
            )

            logger.info(
                "audit_event_archived_to_s3",
                event_id=event.event_id,
                bucket=self.s3_bucket,
                key=key,
            )

        except Exception as e:
            logger.error(
                "s3_archive_failed",
                event_id=event.event_id,
                error=str(e),
            )

    async def get_event(self, incident_id: str, event_id: str) -> Optional[AuditEvent]:
        """Get a specific audit event."""
        r = await self._get_redis()
        key = f"audit:{incident_id}:{event_id}"
        data = await r.get(key)

        if data:
            return AuditEvent(**json.loads(data))
        return None

    async def get_incident_events(
        self,
        incident_id: str,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get all audit events for an incident."""
        r = await self._get_redis()
        event_ids = await r.lrange(f"audit:index:{incident_id}", 0, limit - 1)

        events = []
        for event_id in event_ids:
            event_id = event_id.decode() if isinstance(event_id, bytes) else event_id
            event = await self.get_event(incident_id, event_id)
            if event:
                events.append(event)

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        return events

    async def verify_chain(self, incident_id: str) -> bool:
        """Verify the integrity of the audit chain."""
        events = await self.get_incident_events(incident_id)

        if not events:
            return True

        # Verify each event
        for i, event in enumerate(events):
            # Verify HMAC
            stored_signature = event.hmac_signature
            event.hmac_signature = None
            expected_signature = self._sign_event(event)
            event.hmac_signature = stored_signature

            if stored_signature != expected_signature:
                logger.error(
                    "audit_chain_verification_failed",
                    event_id=event.event_id,
                    reason="HMAC mismatch",
                )
                return False

            # Verify chain link
            if i > 0:
                expected_previous = events[i - 1].hmac_signature
                if event.previous_hash != expected_previous:
                    logger.error(
                        "audit_chain_verification_failed",
                        event_id=event.event_id,
                        reason="Chain link broken",
                    )
                    return False

        logger.info(
            "audit_chain_verified",
            incident_id=incident_id,
            events_count=len(events),
        )
        return True

    async def get_agent_runs(
        self,
        incident_id: str,
        agent_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get agent runs for DTP 3.3 agent-runs data product."""
        events = await self.get_incident_events(incident_id)

        runs = []
        for event in events:
            if event.event_type in (
                AuditEventType.AGENT_RUN_STARTED,
                AuditEventType.AGENT_RUN_COMPLETED,
                AuditEventType.AGENT_RUN_FAILED,
            ):
                if agent_type and event.agent_type != agent_type:
                    continue

                runs.append({
                    "run_id": event.event_id,
                    "incident_id": event.incident_id,
                    "agent_type": event.agent_type,
                    "started_at": event.timestamp.isoformat(),
                    "completed_at": event.details.get("completed_at"),
                    "status": event.status,
                    "input_payload": event.details.get("input"),
                    "output_payload": event.details.get("output"),
                    "token_usage": event.details.get("token_usage"),
                    "duration_seconds": event.details.get("duration_seconds"),
                })

        return runs

    async def get_metrics(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Get audit metrics for monitoring."""
        r = await self._get_redis()

        # Get all incident IDs
        keys = await r.keys("audit:index:*")
        incident_ids = [
            k.decode().replace("audit:index:", "")
            for k in keys
        ]

        total_events = 0
        agent_runs = 0
        approvals = 0

        for incident_id in incident_ids:
            event_ids = await r.lrange(f"audit:index:{incident_id}", 0, -1)
            total_events += len(event_ids)

            for event_id in event_ids:
                event = await self.get_event(incident_id, event_id.decode())
                if event:
                    if event.event_type.startswith("agent_run"):
                        agent_runs += 1
                    elif event.event_type.startswith("approval"):
                        approvals += 1

        return {
            "total_incidents": len(incident_ids),
            "total_events": total_events,
            "agent_runs": agent_runs,
            "approvals": approvals,
        }
