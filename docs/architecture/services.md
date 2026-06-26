# Services

## Overview

Cobalto includes three core services for operational control: Approval, Audit, and Case Management.

```
+----------------+     +----------------+     +----------------+
|   APPROVAL     |     |    AUDIT       |     |    CASE        |
|   SERVICE      |     |    SERVICE     |     |    SERVICE     |
|                |     |                |     |                |
| Human gates    |     | Immutable logs |     | Case tracking  |
| Slack/Teams    |     | HMAC chain     |     | TheHive sync   |
| Timeout mgmt   |     | S3 archival    |     | SLA monitoring |
+----------------+     +----------------+     +----------------+
```

## Approval Service

Gates high-risk actions requiring human approval.

### Features

- Slack and Teams integration
- HMAC signature verification
- Configurable timeout
- Automatic escalation

### Usage

```python
from cobalto.agent.approval import ApprovalService

service = ApprovalService(
    hmac_secret="your-secret",
    slack_token="xoxb-...",
    teams_webhook="https://...",
)

# Create approval request
request = await service.create_request(
    action="block_ip",
    parameters={"ip": "203.0.113.45", "reason": "Malware C2"},
    requested_by="silver-response",
    timeout_minutes=10,
)

# Request includes:
# - request_id: "req-abc123"
# - hmac_signature: "sha256=..."
# - slack_message_ts: "1234567890.123456"

# Check approval status
status = await service.check_status(request.request_id)
# status: "pending" | "approved" | "rejected" | "expired"

# Approve (via webhook callback)
await service.approve(
    request_id="req-abc123",
    approved_by="analyst@company.com",
    hmac_signature="...",
)
```

### Slack Integration

```
+-----------------------------------------+
|  [COBALTO] Approval Required            |
|                                         |
|  Action: block_ip                       |
|  IP: 203.0.113.45                       |
|  Reason: Malware C2 communication       |
|  Requested by: silver-response          |
|  Timeout: 10 minutes                    |
|                                         |
|  [Approve]  [Reject]  [View Details]    |
+-----------------------------------------+
```

### HMAC Verification

```python
import hmac
import hashlib

# Generate signature
message = f"{request_id}:{action}:{timestamp}"
signature = hmac.new(
    secret.encode(),
    message.encode(),
    hashlib.sha256,
).hexdigest()

# Verify signature
expected = hmac.new(
    secret.encode(),
    f"{request_id}:{action}:{timestamp}".encode(),
    hashlib.sha256,
).hexdigest()

assert signature == expected
```

## Audit Service

Immutable audit trail for compliance and forensics.

### Features

- HMAC-sealed log entries
- Chain of custody (each entry links to previous)
- S3 archival
- Tamper detection

### Usage

```python
from cobalto.agent.audit import AuditService

service = AuditService(
    hmac_secret="your-secret",
    s3_bucket="cobalto-audit-logs",
)

# Log an event
event = await service.log_event(
    event_type="alert.triage.completed",
    alert_id="alert-123",
    agent="silver-triage",
    details={
        "severity": "high",
        "confidence": 0.85,
        "mitre_techniques": ["T1110"],
    },
)

# Event includes:
# - event_id: "evt-xyz789"
# - hmac_signature: "sha256=..."
# - previous_hash: "abc123..."
# - chain_position: 1234

# Verify chain integrity
is_valid = await service.verify_chain(
    start_position=1230,
    end_position=1234,
)
# True if chain is intact

# Query audit log
events = await service.query(
    alert_id="alert-123",
    event_type="alert.*",
    start_time="2026-01-01T00:00:00Z",
)
```

### HMAC Chain

```
Event 1                Event 2                Event 3
+-------+              +-------+              +-------+
| Data  |              | Data  |              | Data  |
+---+---+              +---+---+              +---+---+
    |                      |                      |
    v                      v                      v
+-------+              +-------+              +-------+
| HMAC  |              | HMAC  |              | HMAC  |
|       |              |       |              |       |
| prev= |----->       | prev= |----->       | prev= |
| null  |              | hash1 |              | hash2 |
+-------+              +-------+              +-------+
```

## Case Service

Integrates with TheHive for case management.

### Features

- Auto-create cases from alerts
- Observable and artifact tracking
- SLA monitoring
- Status synchronization

### Usage

```python
from cobalto.agent.case_service import CaseService, CaseSeverity, CasePriority

service = CaseService(
    thehive_url="http://thehive:9000/api",
    thehive_token="your-token",
)

# Create case from alert
case = await service.create_case_from_alert(
    alert_id="alert-123",
    alert_data={
        "rule_id": 5712,
        "rule_level": 8,
        "source_ip": "203.0.113.45",
    },
    severity=CaseSeverity.HIGH,
    priority=CasePriority.HIGH,
)

# Case includes:
# - case_id: "Case-1234"
# - thehive_id: "ASE12345"
# - status: "open"

# Add observable
await service.add_observable(
    case_id="Case-1234",
    observable_type="ip",
    observable_value="203.0.113.45",
    tlp="amber",
    tags=["malicious", "c2"],
)

# Check SLA
sla = await service.check_sla("Case-1234")
# sla: {"status": "on_track", "remaining_hours": 18.5}

# Update status
await service.update_status(
    case_id="Case-1234",
    status="resolved",
    resolution="blocked_ip",
)
```

### Severity Mapping

| Cobalto | TheHive |
|---------|---------|
| Critical | P1 |
| High | P2 |
| Medium | P3 |
| Low | P4 |

## Configuration

```bash
# Approval Service
APPROVAL_HMAC_SECRET=your-secret
SLACK_BOT_TOKEN=xoxb-...
SLACK_CHANNEL=#soc-alerts
TEAMS_WEBHOOK_URL=https://...

# Audit Service
AUDIT_HMAC_SECRET=your-secret
AUDIT_S3_BUCKET=cobalto-audit-logs
AUDIT_RETENTION_DAYS=365

# Case Service
THEHIVE_URL=http://thehive:9000/api
THEHIVE_TOKEN=your-token
```

## Testing

```bash
# Run service tests
python -m pytest tests/unit/agent/test_services.py -v
```
