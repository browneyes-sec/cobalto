# Magenta Supervisor

## Overview

The Magenta Supervisor orchestrates Silver agents using the OSCAR framework. It routes alerts to appropriate agents and manages the investigation lifecycle.

```
                        +------------------+
                        |  Alert Incoming  |
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        |  O - ORIENT      |
                        |  Parse & Classify|
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        |  S - STRATEGIZE  |
                        |  Select Agents   |
                        +--------+---------+
                                 |
                                 v
                  +--------------+--------------+
                  |                             |
                  v                             v
         +----------------+           +----------------+
         |  C - COLLECT   |           |  C - COLLECT   |
         |  Triage Agent  |           |  Intel Agent   |
         +-------+--------+           +-------+--------+
                 |                             |
                 +--------------+--------------+
                                |
                                v
                        +------------------+
                        |  A - ANALYZE     |
                        |  Analysis Agent  |
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        |  R - REPORT      |
                        |  Docs & Response |
                        +------------------+
```

## OSCAR Framework

| Phase | Agent | Actions |
|-------|-------|---------|
| **Orient** | Supervisor | Parse alert, classify type, assess urgency |
| **Strategize** | Supervisor | Select agents, plan investigation |
| **Collect** | Triage + Intel | Gather context, enrich IOCs |
| **Analyze** | Analysis | Deep investigation, correlation |
| **Report** | Docs + Response | Document findings, execute response |

## Usage

```python
from services.langgraph.agents.supervisor import MagentaSupervisor

supervisor = MagentaSupervisor()
result = await supervisor.run({
    "alert_id": "alert-123",
    "alert": {
        "rule_id": 5712,
        "rule_level": 8,
        "source_ip": "203.0.113.45",
    },
    "context": {
        "tenant_id": "acme-corp",
    },
})

# Result includes:
# - status: "completed" | "failed" | "pending_approval"
# - routing: { "triage": "executed", "analysis": "executed", ... }
# - duration_ms: 1234.56
# - agents_called: ["triage", "analysis", "response"]
```

## Routing Logic

```python
def _route_alert(self, state: AgentState) -> str:
    """Route alert based on severity and type."""
    alert = state["alert"]
    severity = alert.get("rule_level", 0)

    # Critical alerts - full pipeline
    if severity >= 10:
        return "triage -> analysis -> response"

    # High alerts - triage + analysis + response (with approval)
    if severity >= 7:
        return "triage -> analysis -> response"

    # Medium alerts - triage + analysis
    if severity >= 4:
        return "triage -> analysis"

    # Low alerts - triage only
    return "triage"
```

## State Machine

```
+-------------+     +-------------+     +-------------+
|   PENDING   | --> |   RUNNING   | --> |  COMPLETED  |
+-------------+     +-------------+     +-------------+
                           |
                           v
                    +-------------+
                    |   FAILED    |
                    +-------------+
                           |
                           v
                    +-------------+
                    |  PENDING_   |
                    |  APPROVAL   |
                    +-------------+
```

## Agent Selection

| Alert Type | Triage | Analysis | Response |
|------------|--------|----------|----------|
| Brute Force | Yes | Yes | Yes (approval) |
| Malware | Yes | Yes | Yes (auto) |
| Phishing | Yes | Yes | Yes (approval) |
| Data Exfil | Yes | Yes | Yes (approval) |
| Recon | Yes | Yes | No |
| Policy Violation | Yes | No | Yes (approval) |

## Configuration

```bash
# Supervisor settings
SUPERVISOR_MAX_CONCURRENT=10
SUPERVISOR_TIMEOUT_SECONDS=300
SUPERVISOR_RETRY_COUNT=3

# Agent settings
TRIAGE_AGENT_ENABLED=true
ANALYSIS_AGENT_ENABLED=true
RESPONSE_AGENT_ENABLED=true
```

## Testing

```bash
# Run supervisor tests
python -m pytest tests/unit/agent/test_supervisor.py -v
```
