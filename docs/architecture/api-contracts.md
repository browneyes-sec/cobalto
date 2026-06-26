# API Contract Reference

This document defines the request/response schemas for all Cobalto platform endpoints.

## Table of Contents

- [POST /agent/analyze](#post-agentanalyze)
- [GET /health](#get-health)
- [GET /ready](#get-ready)
- [GET /graph/visualize](#get-graphvisualize)
- [POST /webhook/wazuh](#post-webhookwazuh)
- [POST /webhook/slack](#post-webhookslack)

---

## POST /agent/analyze

Triggers the LangGraph agent to analyze an alert payload through the full SOC workflow.

### Request

**Headers**

| Header          | Value              | Required |
|-----------------|--------------------|----------|
| `Content-Type`  | `application/json` | Yes      |
| `Authorization` | `Bearer <token>`   | Yes      |
| `X-Request-ID`  | `<uuid>`           | No       |

**Request Schema: `AlertPayload`**

```json
{
  "alert_id": "string (required) — Unique alert identifier",
  "source": "string (required) — Origin system (wazuh, siem, manual)",
  "timestamp": "string (required) — ISO 8601 timestamp",
  "severity": "string (required) — One of: low, medium, high, critical",
  "title": "string (required) — Human-readable alert title",
  "description": "string (optional) — Detailed alert description",
  "indicators": [
    {
      "type": "string — ip, domain, url, hash_md5, hash_sha1, hash_sha256, email",
      "value": "string — Indicator value",
      "context": "string (optional) — Additional context"
    }
  ],
  "host": {
    "hostname": "string (optional)",
    "ip": "string (optional)",
    "os": "string (optional)"
  },
  "process": {
    "pid": "integer (optional)",
    "name": "string (optional)",
    "command_line": "string (optional)"
  },
  "raw_event": "object (optional) — Original alert data from source"
}
```

### Response

**Status Codes**

| Code | Description                                    |
|------|------------------------------------------------|
| 200  | Analysis completed successfully                |
| 202  | Analysis accepted and queued for processing     |
| 400  | Invalid request payload                        |
| 401  | Unauthorized — invalid or missing token         |
| 422  | Unprocessable entity — validation failed        |
| 429  | Rate limited                                   |
| 500  | Internal server error                          |

**Response Schema: `AgentResult`**

```json
{
  "case_id": "string — TheHive case identifier",
  "alert_id": "string — Original alert ID",
  "status": "string — completed, failed, in_progress",
  "verdict": "string — malicious, suspicious, benign, unknown",
  "confidence": "number (0.0-1.0) — Agent confidence score",
  "severity": "string — low, medium, high, critical",
  "recommendation": "string — Remediation recommendation",
  "observables": [
    {
      "type": "string — Observable type",
      "value": "string — Observable value",
      "enrichment": {
        "source": "string — Enrichment source (VirusTotal, Shodan, etc.)",
        "results": "object — Source-specific results",
        "score": "number (0-100) — Threat score"
      }
    }
  ],
  "timeline": [
    {
      "step": "string — Workflow step name",
      "status": "string — success, failure, skipped",
      "duration_ms": "integer — Step duration in milliseconds",
      "output": "object (optional) — Step output"
    }
  ],
  "mitre_attack": [
    {
      "tactic": "string — MITRE ATT&CK tactic",
      "technique": "string — MITRE ATT&CK technique",
      "technique_id": "string — e.g., T1059"
    }
  ],
  "created_at": "string — ISO 8601 timestamp",
  "completed_at": "string (optional) — ISO 8601 timestamp"
}
```

**Example 200 Response**

```json
{
  "case_id": "CASE-2025-0042",
  "alert_id": "wazuh-2025-0115-001",
  "status": "completed",
  "verdict": "malicious",
  "confidence": 0.94,
  "severity": "critical",
  "recommendation": "Isolate host 10.0.5.12 immediately. Block IP 185.220.101.34 at perimeter firewall. Reset credentials for user jdoe.",
  "observables": [
    {
      "type": "ip",
      "value": "185.220.101.34",
      "enrichment": {
        "source": "VirusTotal",
        "results": {
          "malicious": 42,
          "suspicious": 8,
          "harmless": 12
        },
        "score": 87
      }
    },
    {
      "type": "hash_sha256",
      "value": "a1b2c3d4e5f6...",
      "enrichment": {
        "source": "VirusTotal",
        "results": {
          "malicious": 58,
          "type": "Trojan.GenericKD.47849219"
        },
        "score": 92
      }
    }
  ],
  "timeline": [
    {"step": "ingest", "status": "success", "duration_ms": 120},
    {"step": "enrich_observables", "status": "success", "duration_ms": 3400},
    {"step": "correlate_ioc", "status": "success", "duration_ms": 890},
    {"step": "llm_analysis", "status": "success", "duration_ms": 4200},
    {"step": "create_case", "status": "success", "duration_ms": 340}
  ],
  "mitre_attack": [
    {"tactic": "Command and Control", "technique": "Application Layer Protocol: Web Protocols", "technique_id": "T1071.001"},
    {"tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "technique_id": "T1041"}
  ],
  "created_at": "2025-01-15T14:23:01.123Z",
  "completed_at": "2025-01-15T14:23:09.953Z"
}
```

---

## GET /health

Liveness probe endpoint. Returns 200 if the service is running.

### Response

**Status Codes**

| Code | Description       |
|------|-------------------|
| 200  | Service is alive  |

```json
{
  "status": "healthy",
  "service": "langgraph-agent",
  "version": "1.2.0",
  "uptime_seconds": 86423
}
```

---

## GET /ready

Readiness probe endpoint. Returns 200 only when all dependencies are available.

### Response

**Status Codes**

| Code | Description                            |
|------|----------------------------------------|
| 200  | Service is ready to accept traffic     |
| 503  | Service is not ready                   |

```json
{
  "status": "ready",
  "checks": {
    "vault": "ok",
    "qdrant": "ok",
    "elasticsearch": "ok",
    "opencti": "ok",
    "cortex": "ok",
    "n8n": "ok"
  }
}
```

---

## GET /graph/visualize

Returns a Mermaid diagram representation of the current workflow graph for debugging and documentation.

### Response

**Status Codes**

| Code | Description       |
|------|-------------------|
| 200  | Diagram generated |

```json
{
  "format": "mermaid",
  "diagram": "graph TD\n    A[Ingest] --> B{Alert Triage}\n    B -->|malware| C[Enrich Observable]\n    B -->|phishing| D[Analyze URL]\n    B -->|brute_force| E[Check Auth Logs]\n    C --> F[LLM Analysis]\n    D --> F\n    E --> F\n    F --> G[Create Case]\n    G --> H[Notify Analyst]"
}
```

---

## POST /webhook/wazuh

Receives alert webhooks from Wazuh manager. Validates the payload and triggers the agent workflow.

### Request

**Headers**

| Header            | Value              | Required |
|-------------------|--------------------|----------|
| `Content-Type`    | `application/json` | Yes      |
| `X-Wazuh-Signature` | `hmac-sha256`   | Yes      |

**Request Schema: Wazuh Alert Payload**

```json
{
  "agent_id": "string — Wazuh agent ID",
  "agent_name": "string — Hostname of the agent",
  "agent_ip": "string — IP address of the agent",
  "rule": {
    "id": "string — Rule ID",
    "level": "integer (1-15) — Alert severity level",
    "description": "string — Rule description",
    "groups": ["array of rule groups"],
    "mitre": {
      "technique": ["array of MITRE technique IDs"]
    }
  },
  "decoder": {
    "name": "string — Decoder name",
    "parent": "string (optional) — Parent decoder"
  },
  "data": {
    "srcip": "string (optional) — Source IP",
    "dstip": "string (optional) — Destination IP",
    "srcport": "string (optional) — Source port",
    "dstport": "string (optional) — Destination port",
    "protocol": "string (optional) — Protocol",
    "action": "string (optional) — Network action",
    "filepath": "string (optional) — File path",
    "md5": "string (optional) — MD5 hash",
    "sha1": "string (optional) — SHA1 hash",
    "sha256": "string (optional) — SHA256 hash",
    "uname": "string (optional) — Process name",
    "pid": "string (optional) — Process ID",
    "command": "string (optional) — Command executed",
    "user": "string (optional) — Username"
  },
  "location": "string — Log source location",
  "timestamp": "string — Alert timestamp (ISO 8601)",
  "output": "string — Full log line"
}
```

### Response

**Status Codes**

| Code | Description                                    |
|------|------------------------------------------------|
| 202  | Webhook accepted, analysis queued              |
| 400  | Invalid payload                                |
| 401  | Invalid signature                              |
| 429  | Rate limited                                   |

```json
{
  "status": "accepted",
  "case_id": "CASE-2025-0043",
  "message": "Alert queued for analysis"
}
```

---

## POST /webhook/slack

Receives Slack interactive message payloads for analyst approval actions (approve/reject/enrich).

### Request

**Headers**

| Header            | Value                    | Required |
|-------------------|--------------------------|----------|
| `Content-Type`    | `application/x-www-form-urlencoded` | Yes |
| `X-Slack-Signature` | `v0=<hmac>`           | Yes      |

**Request Schema: Slack Interactive Payload**

```json
{
  "type": "interactive",
  "actions": [
    {
      "action_id": "string — approve_case | reject_case | enrich_observable",
      "type": "button",
      "value": "string — Case or observable ID",
      "text": {
        "type": "plain_text",
        "text": "string — Button label"
      }
    }
  ],
  "container": {
    "type": "message",
    "message_ts": "string — Slack message timestamp"
  },
  "user": {
    "id": "string — Slack user ID",
    "username": "string — Slack username"
  },
  "team": {
    "id": "string — Slack workspace ID"
  },
  "channel": {
    "id": "string — Slack channel ID"
  },
  "response_url": "string — URL to post delayed response"
}
```

### Response

**Status Codes**

| Code | Description                    |
|------|--------------------------------|
| 200  | Action processed               |
| 400  | Invalid payload                |
| 401  | Invalid Slack signature        |

```json
{
  "response_action": "update",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Case CASE-2025-0042* — Approved by @analyst1\nStatus: Investigating"
      }
    }
  ]
}
```

---

## Error Response Format

All endpoints use the following error response schema:

```json
{
  "error": "string — Error code",
  "message": "string — Human-readable error message",
  "details": "object (optional) — Additional error context",
  "request_id": "string — Request correlation ID"
}
```
