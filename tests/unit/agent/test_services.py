"""Tests for Approval, Audit, and Case services."""

import pytest
from datetime import datetime, timedelta
from cobalto.agent.approval import ApprovalService, ApprovalRequest, ApprovalStatus, ApprovalChannel
from cobalto.agent.audit import AuditService, AuditEvent, AuditEventType
from cobalto.agent.case_service import CaseService, CaseSeverity, CasePriority, CaseTemplate


class TestApprovalService:
    """Tests for ApprovalService."""

    def test_service_initialization(self):
        service = ApprovalService(
            redis_url="redis://localhost:6379",
            hmac_secret="test-secret",
        )
        assert service.hmac_secret == "test-secret"
        assert service.default_timeout_minutes == 10

    def test_approval_request_creation(self):
        request = ApprovalRequest(
            request_id="test-123",
            incident_id="incident-456",
            alert_id="alert-789",
            actions=[{"action_type": "block_ip", "target": "10.0.0.1"}],
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        assert request.request_id == "test-123"
        assert request.status == ApprovalStatus.PENDING
        assert len(request.actions) == 1

    def test_approval_request_to_dict(self):
        request = ApprovalRequest(
            request_id="test-123",
            incident_id="incident-456",
            alert_id="alert-789",
            actions=[],
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        data = request.to_dict()
        assert data["request_id"] == "test-123"
        assert data["status"] == "pending"
        assert "expires_at" in data

    def test_hmac_signature_generation(self):
        service = ApprovalService(hmac_secret="test-secret")
        request = ApprovalRequest(
            request_id="test-123",
            incident_id="incident-456",
            alert_id="alert-789",
            actions=[],
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
        signature = service._sign_request(request)
        assert len(signature) == 64  # SHA256 hex digest


class TestAuditService:
    """Tests for AuditService."""

    def test_service_initialization(self):
        service = AuditService(
            redis_url="redis://localhost:6379",
            hmac_secret="test-secret",
        )
        assert service.hmac_secret == "test-secret"

    def test_audit_event_creation(self):
        event = AuditEvent(
            event_type=AuditEventType.AGENT_RUN_STARTED,
            incident_id="incident-456",
            agent_type="triage",
            agent_id="triage-123",
        )
        assert event.event_type == AuditEventType.AGENT_RUN_STARTED
        assert event.incident_id == "incident-456"
        assert event.event_id is not None

    def test_audit_event_to_dict(self):
        event = AuditEvent(
            event_type=AuditEventType.ACTION_EXECUTED,
            incident_id="incident-456",
            action="block_ip",
            target="10.0.0.1",
        )
        data = event.to_dict()
        assert data["event_type"] == "action_executed"
        assert data["action"] == "block_ip"
        assert data["target"] == "10.0.0.1"

    def test_hmac_signature_generation(self):
        service = AuditService(hmac_secret="test-secret")
        event = AuditEvent(
            event_type=AuditEventType.AGENT_RUN_COMPLETED,
            incident_id="incident-456",
        )
        signature = service._sign_event(event)
        assert len(signature) == 64

    def test_event_types(self):
        assert AuditEventType.AGENT_RUN_STARTED.value == "agent_run_started"
        assert AuditEventType.AGENT_RUN_COMPLETED.value == "agent_run_completed"
        assert AuditEventType.ACTION_EXECUTED.value == "action_executed"
        assert AuditEventType.APPROVAL_GRANTED.value == "approval_granted"


class TestCaseService:
    """Tests for CaseService."""

    def test_service_initialization(self):
        service = CaseService(
            thehive_url="http://localhost:9000",
            thehive_token="test-token",
        )
        assert service.thehive_url == "http://localhost:9000"
        assert service.default_owner == "soc-team"

    def test_severity_mapping(self):
        service = CaseService()
        assert service._map_severity(CaseSeverity.LOW) == 1
        assert service._map_severity(CaseSeverity.MEDIUM) == 2
        assert service._map_severity(CaseSeverity.HIGH) == 3
        assert service._map_severity(CaseSeverity.CRITICAL) == 4

    def test_priority_mapping(self):
        service = CaseService()
        assert service._map_priority(CasePriority.P1) == 1
        assert service._map_priority(CasePriority.P2) == 2
        assert service._map_priority(CasePriority.P3) == 3
        assert service._map_priority(CasePriority.P4) == 4

    def test_observable_type_mapping(self):
        service = CaseService()
        assert service._map_observable_type("ip") == "IP"
        assert service._map_observable_type("domain") == "domain"
        assert service._map_observable_type("hash") == "hash"
        assert service._map_observable_type("user") == "user"

    def test_case_template(self):
        template = CaseTemplate(
            title="Ransomware Incident",
            description="Ransomware detected",
            severity=CaseSeverity.CRITICAL,
            priority=CasePriority.P1,
            tags=["ransomware", "critical"],
        )
        assert template.title == "Ransomware Incident"
        assert template.severity == CaseSeverity.CRITICAL
