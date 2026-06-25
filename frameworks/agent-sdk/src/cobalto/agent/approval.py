"""
Approval Service

Human-in-the-loop approval gate for high-risk response actions.
Supports Slack and Teams notifications with timeout handling.

DTP 7.2: Agent Governance Lifecycle
- Approval gates are architectural control points, not UX features
- Accountability is non-negotiable in an agentic system
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import hmac
import json
import redis.asyncio as redis
import httpx
import structlog

logger = structlog.get_logger(__name__)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ApprovalChannel(str, Enum):
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"


class ApprovalRequest(BaseModel):
    """Approval request for high-risk actions."""
    request_id: str
    incident_id: str
    alert_id: str
    actions: List[Dict[str, Any]]
    requested_by: str = "magenta-supervisor"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    channel: ApprovalChannel = ApprovalChannel.SLACK
    approver: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    hmac_signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "actions": self.actions,
            "requested_by": self.requested_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status.value,
            "channel": self.channel.value,
            "approver": self.approver,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "rejection_reason": self.rejection_reason,
        }


class ApprovalService:
    """
    Approval service for human-in-the-loop gate.

    Features:
    - Multi-channel notification (Slack, Teams)
    - Timeout handling
    - HMAC signature verification
    - Redis-backed state management
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        hmac_secret: str = "approval-secret-change-in-production",
        slack_token: Optional[str] = None,
        teams_webhook: Optional[str] = None,
        default_timeout_minutes: int = 10,
    ):
        self.redis_url = redis_url
        self.hmac_secret = hmac_secret
        self.slack_token = slack_token
        self.teams_webhook = teams_webhook
        self.default_timeout_minutes = default_timeout_minutes
        self._redis: Optional[redis.Redis] = None

    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(self.redis_url)
        return self._redis

    async def create_approval_request(
        self,
        incident_id: str,
        alert_id: str,
        actions: List[Dict[str, Any]],
        channel: ApprovalChannel = ApprovalChannel.SLACK,
        timeout_minutes: Optional[int] = None,
    ) -> ApprovalRequest:
        """Create an approval request."""
        import uuid

        timeout = timeout_minutes or self.default_timeout_minutes
        request_id = f"approval-{uuid.uuid4().hex[:12]}"

        request = ApprovalRequest(
            request_id=request_id,
            incident_id=incident_id,
            alert_id=alert_id,
            actions=actions,
            expires_at=datetime.utcnow() + timedelta(minutes=timeout),
            channel=channel,
        )

        # Generate HMAC signature
        request.hmac_signature = self._sign_request(request)

        # Store in Redis
        r = await self._get_redis()
        key = f"approval:{request_id}"
        await r.setex(
            key,
            timeout * 60,  # TTL in seconds
            json.dumps(request.to_dict()),
        )

        # Add to pending queue
        await r.lpush("approval:pending", request_id)

        logger.info(
            "approval_request_created",
            request_id=request_id,
            incident_id=incident_id,
            actions_count=len(actions),
            channel=channel.value,
            expires_at=request.expires_at.isoformat(),
        )

        return request

    async def send_notification(
        self,
        request: ApprovalRequest,
    ) -> bool:
        """Send approval notification to specified channel."""
        try:
            if request.channel == ApprovalChannel.SLACK:
                return await self._send_slack_notification(request)
            elif request.channel == ApprovalChannel.TEAMS:
                return await self._send_teams_notification(request)
            else:
                logger.warning("unsupported_channel", channel=request.channel)
                return False
        except Exception as e:
            logger.error(
                "notification_send_failed",
                request_id=request.request_id,
                channel=request.channel.value,
                error=str(e),
            )
            return False

    async def _send_slack_notification(self, request: ApprovalRequest) -> bool:
        """Send Slack approval notification."""
        if not self.slack_token:
            logger.warning("slack_token_not_configured")
            return False

        # Build action summary
        actions_text = "\n".join([
            f"• {a.get('action_type', 'unknown')}: {a.get('target', 'unknown')} ({a.get('risk_level', 'low')} risk)"
            for a in request.actions
        ])

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
                    {"type": "mrkdwn", "text": f"*Request ID:*\n{request.request_id}"},
                    {"type": "mrkdwn", "text": f"*Incident:*\n{request.incident_id}"},
                    {"type": "mrkdwn", "text": f"*Alert:*\n{request.alert_id}"},
                    {"type": "mrkdwn", "text": f"*Expires:*\n{request.expires_at.strftime('%H:%M UTC')}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Actions:*\n{actions_text}"},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve"},
                        "style": "primary",
                        "action_id": f"approve_{request.request_id}",
                        "value": request.request_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject"},
                        "style": "danger",
                        "action_id": f"reject_{request.request_id}",
                        "value": request.request_id,
                    },
                ],
            },
        ]

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {self.slack_token}",
                    "Content-Type": "application/json",
                },
                json={
                    "channel": "#soc-approvals",
                    "text": f"Approval required for {request.incident_id}",
                    "blocks": blocks,
                },
                timeout=10.0,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    "slack_notification_sent",
                    request_id=request.request_id,
                    ok=result.get("ok"),
                )
                return result.get("ok", False)
            return False

    async def _send_teams_notification(self, request: ApprovalRequest) -> bool:
        """Send Teams approval notification."""
        if not self.teams_webhook:
            logger.warning("teams_webhook_not_configured")
            return False

        # Build Adaptive Card
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF6B35",
            "summary": f"Approval Required: {request.incident_id}",
            "sections": [
                {
                    "activityTitle": "🔒 Action Requires Approval",
                    "facts": [
                        {"name": "Request ID", "value": request.request_id},
                        {"name": "Incident", "value": request.incident_id},
                        {"name": "Alert", "value": request.alert_id},
                        {"name": "Expires", "value": request.expires_at.strftime("%H:%M UTC")},
                    ],
                    "text": "\n".join([
                        f"• {a.get('action_type', 'unknown')}: {a.get('target', 'unknown')}"
                        for a in request.actions
                    ]),
                }
            ],
            "potentialAction": [
                {
                    "@type": "HttpPOST",
                    "name": "Approve",
                    "target": f"http://localhost:8001/approval/{request.request_id}/approve",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                },
                {
                    "@type": "HttpPOST",
                    "name": "Reject",
                    "target": f"http://localhost:8001/approval/{request.request_id}/reject",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                },
            ],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.teams_webhook,
                json=card,
                timeout=10.0,
            )
            return response.status_code == 200

    async def approve_request(
        self,
        request_id: str,
        approver: str,
        signature: Optional[str] = None,
    ) -> ApprovalRequest:
        """Approve an approval request."""
        r = await self._get_redis()
        key = f"approval:{request_id}"
        data = await r.get(key)

        if not data:
            raise ValueError(f"Approval request {request_id} not found")

        request_data = json.loads(data)
        request = ApprovalRequest(**request_data)

        # Verify HMAC if provided
        if signature and request.hmac_signature:
            if not self._verify_signature(request, signature):
                raise ValueError("Invalid HMAC signature")

        # Check if expired
        if datetime.fromisoformat(request.expires_at) < datetime.utcnow():
            request.status = ApprovalStatus.TIMEOUT
            await r.set(key, json.dumps(request.to_dict()))
            raise ValueError("Approval request has expired")

        # Update status
        request.status = ApprovalStatus.APPROVED
        request.approver = approver
        request.approved_at = datetime.utcnow()

        # Store updated request
        await r.set(key, json.dumps(request.to_dict()))

        # Remove from pending queue
        await r.lrem("approval:pending", 0, request_id)

        # Add to completed queue
        await r.lpush("approval:completed", request_id)

        logger.info(
            "approval_granted",
            request_id=request_id,
            approver=approver,
        )

        return request

    async def reject_request(
        self,
        request_id: str,
        approver: str,
        reason: str = "Rejected by analyst",
    ) -> ApprovalRequest:
        """Reject an approval request."""
        r = await self._get_redis()
        key = f"approval:{request_id}"
        data = await r.get(key)

        if not data:
            raise ValueError(f"Approval request {request_id} not found")

        request_data = json.loads(data)
        request = ApprovalRequest(**request_data)

        # Update status
        request.status = ApprovalStatus.REJECTED
        request.approver = approver
        request.rejection_reason = reason

        # Store updated request
        await r.set(key, json.dumps(request.to_dict()))

        # Remove from pending queue
        await r.lrem("approval:pending", 0, request_id)

        # Add to completed queue
        await r.lpush("approval:completed", request_id)

        logger.info(
            "approval_rejected",
            request_id=request_id,
            approver=approver,
            reason=reason,
        )

        return request

    async def check_timeouts(self) -> List[str]:
        """Check for timed-out approval requests."""
        r = await self._get_redis()
        pending_ids = await r.lrange("approval:pending", 0, -1)

        timed_out = []
        for request_id in pending_ids:
            request_id = request_id.decode() if isinstance(request_id, bytes) else request_id
            key = f"approval:{request_id}"
            data = await r.get(key)

            if data:
                request_data = json.loads(data)
                expires_at = datetime.fromisoformat(request_data["expires_at"])

                if expires_at < datetime.utcnow():
                    # Mark as timed out
                    request_data["status"] = ApprovalStatus.TIMEOUT.value
                    await r.set(key, json.dumps(request_data))

                    # Move to completed
                    await r.lrem("approval:pending", 0, request_id)
                    await r.lpush("approval:completed", request_id)

                    timed_out.append(request_id)

                    logger.warning(
                        "approval_timed_out",
                        request_id=request_id,
                    )

        return timed_out

    async def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get an approval request by ID."""
        r = await self._get_redis()
        key = f"approval:{request_id}"
        data = await r.get(key)

        if data:
            return ApprovalRequest(**json.loads(data))
        return None

    async def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending approval requests."""
        r = await self._get_redis()
        pending_ids = await r.lrange("approval:pending", 0, -1)

        requests = []
        for request_id in pending_ids:
            request_id = request_id.decode() if isinstance(request_id, bytes) else request_id
            request = await self.get_request(request_id)
            if request and request.status == ApprovalStatus.PENDING:
                requests.append(request)

        return requests

    def _sign_request(self, request: ApprovalRequest) -> str:
        """Generate HMAC signature for request."""
        message = json.dumps(request.to_dict(), sort_keys=True)
        return hmac.new(
            self.hmac_secret.encode(),
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

    def _verify_signature(self, request: ApprovalRequest, signature: str) -> bool:
        """Verify HMAC signature."""
        expected = self._sign_request(request)
        return hmac.compare_digest(expected, signature)
