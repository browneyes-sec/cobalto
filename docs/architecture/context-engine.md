# Context Engine

## Overview

The Context Engine implements a 5-layer model that provides Silver agents with comprehensive context for decision-making. Each layer serves a specific purpose and can be independently tested.

```
+----------------------------------------------------+
|              CONTEXT PACKAGE                        |
|                                                    |
|  +----------------------------------------------+  |
|  | Layer 1: SEMANTIC                            |  |
|  | - Tenant configuration                      |  |
|  | - Asset criticality                         |  |
|  | - SLA tier                                  |  |
|  | - Compliance requirements                   |  |
|  +----------------------------------------------+  |
|  | Layer 2: OPERATIONAL                         |  |
|  | - Prior alerts (72h window)                 |  |
|  | - Open cases                                |  |
|  | - Alert velocity                            |  |
|  | - Burst detection                           |  |
|  +----------------------------------------------+  |
|  | Layer 3: INTELLIGENCE                        |  |
|  | - MITRE ATT&CK techniques (RAG)            |  |
|  | - OpenCTI indicators                        |  |
|  | - Threat actors                             |  |
|  | - CVEs                                      |  |
|  +----------------------------------------------+  |
|  | Layer 4: POLICY                              |  |
|  | - Agent autonomy levels                     |  |
|  | - Allowed actions                           |  |
|  | - High-risk approval requirements          |  |
|  | - Rate limits                               |  |
|  +----------------------------------------------+  |
|  | Layer 5: MEMORY                              |  |
|  | - Prior agent runs (sliding window)        |  |
|  | - Full context for last 5 runs             |  |
|  | - Summarized context for older runs        |  |
|  +----------------------------------------------+  |
+----------------------------------------------------+
```

## Usage

### Building Context

```python
from cobalto.context import ContextBuilder

# Initialize builder
builder = ContextBuilder(
    qdrant_url="http://qdrant:6333",
    redis_url="redis://redis:6379",
    opencti_url="http://opencti:4000/graphql",
)

# Build context for an alert
context_package = await builder.build(
    alert_id="alert-123",
    tenant_id="tenant-acme",
    alert_data={
        "rule_id": 5712,
        "rule_level": 8,
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
    },
)

# Use in agent prompt
prompt_context = context_package.to_prompt_context()
```

### Layer Access

```python
# Semantic layer - business context
semantic = context_package.semantic
print(f"Tenant: {semantic.tenant_id}")
print(f"Criticality: {semantic.asset_criticality}")
print(f"SLA: {semantic.sla_tier}")

# Operational layer - current state
operational = context_package.operational
print(f"Alerts (72h): {operational.prior_alerts_count}")
print(f"Open cases: {operational.open_cases_count}")
print(f"Velocity: {operational.alert_velocity}")

# Intelligence layer - threat intel
intelligence = context_package.intelligence
print(f"MITRE techniques: {intelligence.mitre_techniques}")
print(f"IOCs found: {intelligence.ioc_count}")

# Policy layer - permissions
policy = context_package.policy
print(f"Autonomy: {policy.autonomy_level}")
print(f"Requires approval: {policy.requires_approval}")

# Memory layer - prior runs
memory = context_package.memory
print(f"Prior runs: {memory.prior_runs_count}")
```

## Layer Details

### Layer 1: Semantic

Business context that doesn't change frequently.

| Field | Type | Description |
|-------|------|-------------|
| `tenant_id` | str | Tenant identifier |
| `asset_criticality` | str | low/medium/high/critical |
| `sla_tier` | str | standard/premium/enterprise |
| `compliance` | list | SOC2, PCI-DSS, HIPAA, etc. |
| `business_hours` | dict | Operating hours |
| `escalation_contacts` | list | Emergency contacts |

### Layer 2: Operational

Real-time operational state.

| Field | Type | Description |
|-------|------|-------------|
| `prior_alerts_count` | int | Alerts in last 72h |
| `open_cases_count` | int | Open investigation cases |
| `alert_velocity` | float | Alerts per hour |
| `is_burst` | bool | Burst detection flag |
| `last_alert_time` | str | ISO timestamp |

### Layer 3: Intelligence

Threat intelligence from RAG and external sources.

| Field | Type | Description |
|-------|------|-------------|
| `mitre_techniques` | list | Matching ATT&CK techniques |
| `mitre_tactics` | list | Related tactics |
| `ioc_count` | int | Indicators of compromise |
| `threat_actors` | list | Associated threat actors |
| `cves` | list | Related vulnerabilities |
| `confidence` | float | Intel confidence score |

### Layer 4: Policy

Agent permissions and constraints.

| Field | Type | Description |
|-------|------|-------------|
| `autonomy_level` | str | low/medium/high |
| `allowed_actions` | list | Permitted response actions |
| `requires_approval` | bool | Human approval needed |
| `approval_timeout` | int | Seconds before escalation |
| `rate_limit` | int | Actions per minute |

### Layer 5: Memory

Historical agent context.

| Field | Type | Description |
|-------|------|-------------|
| `prior_runs_count` | int | Total prior runs |
| `recent_runs` | list | Last 5 runs (full detail) |
| `summarized_runs` | list | Older runs (summarized) |
| `success_rate` | float | Historical success rate |
| `avg_response_time` | float | Average response time |

## Integration

### With Silver Triage

```python
from services.langgraph.agents.triage import SilverTriageAgent

agent = SilverTriageAgent()
result = await agent.run({
    "alert_id": "alert-123",
    "context": context_package.to_prompt_context(),
})
```

### With Silver Analysis

```python
from services.langgraph.agents.analysis import SilverAnalysisAgent

agent = SilverAnalysisAgent()
result = await agent.run({
    "alert_id": "alert-123",
    "context": context_package.to_prompt_context(),
})
```

## Configuration

Environment variables:

```bash
# Context Engine
QDRANT_URL=http://qdrant:6333
REDIS_URL=redis://redis:6379
OPENCTI_URL=http://opencti:4000/graphql
OPENCTI_TOKEN=your-token

# Memory settings
MEMORY_WINDOW_SIZE=5
MEMORY_SUMMARY_THRESHOLD=3
```

## Testing

```bash
# Run context engine tests
python -m pytest frameworks/context-engine/tests/ -v

# Run with coverage
python -m pytest frameworks/context-engine/tests/ --cov=cobalto.context
```
