# Cobalto Architecture

## System Overview

Cobalto is an agentic SOC/MDR platform that automates threat detection, investigation, and response using AI agents orchestrated by a supervisor.

```
                              +-----------------+
                              |     Wazuh       |
                              |    (SIEM)       |
                              +--------+--------+
                                       |
                                       v
+------------------+    +------------------+    +------------------+
|    n8n (SOAR)    |    |  Webhook Receiver|    |  External SIEM   |
|  Workflow Engine |    |  /webhook/wazuh  |    |  /webhook/generic|
+--------+---------+    +--------+---------+    +--------+---------+
         |                       |                       |
         +-----------------------+-----------------------+
                                 |
                                 v
                    +--------------------------+
                    |    MAGENTA SUPERVISOR     |
                    |    (OSCAR Framework)      |
                    |                          |
                    |  O - Orient              |
                    |  S - Strategize          |
                    |  C - Collect             |
                    |  A - Analyze             |
                    |  R - Report              |
                    +-----------+--------------+
                                |
            +-------------------+-------------------+
            |                   |                   |
            v                   v                   v
   +----------------+  +----------------+  +----------------+
   |  SILVER TRIAGE |  | SILVER ANALYSIS|  | SILVER RESPONSE|
   |                |  |                |  |                |
   | - MITRE RAG    |  | - OpenCTI      |  | - N8N Execute  |
   | - Cortex       |  | - MISP         |  | - Wazuh AR     |
   | - VT Lookup    |  | - ES Query     |  | - Firewall     |
   +-------+--------+  +-------+--------+  +-------+--------+
           |                   |                   |
           v                   v                   v
   +----------------------------------------------------+
   |              CONTEXT ENGINE (5-Layer)               |
   |                                                    |
   |  1. Semantic     - Business context                |
   |  2. Operational  - Current state                   |
   |  3. Intelligence - Threat intel RAG                |
   |  4. Policy       - Agent permissions               |
   |  5. Memory       - Prior runs                      |
   +----------------------------------------------------+
           |                   |                   |
           v                   v                   v
   +----------------+  +----------------+  +----------------+
   |   APPROVAL     |  |    AUDIT       |  |    CASE        |
   |   SERVICE      |  |    SERVICE     |  |    SERVICE     |
   |                |  |                |  |                |
   | - Slack/Teams  |  | - HMAC-sealed  |  | - TheHive      |
   | - HMAC sigs    |  | - Chain of     |  | - Auto-create  |
   | - Timeout      |  |   custody      |  | - SLA track    |
   +----------------+  +----------------+  +----------------+
```

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Orchestration** | LangGraph | Agent state machine |
| **AI Models** | Groq Llama 3.3, GPT-4o | LLM inference |
| **Vector DB** | Qdrant | RAG storage |
| **Message Queue** | RabbitMQ | Async processing |
| **Cache** | Redis | Session/state |
| **Database** | PostgreSQL | Persistent storage |
| **SIEM** | Wazuh | Alert ingestion |
| **Threat Intel** | OpenCTI | Intelligence feeds |
| **Case Mgmt** | TheHive | Incident tracking |
| **SOAR** | n8n | Workflow automation |
| **Monitoring** | Prometheus + Grafana | Observability |
| **Secrets** | HashiCorp Vault | Secrets management |
| **IaC** | Terraform + Helm | Infrastructure |

## Data Flow

```
1. Alert Ingestion
   Wazuh --> n8n --> /webhook/wazuh --> Supervisor

2. Triage (Automatic)
   Supervisor --> Context Engine --> Silver Triage
   Silver Triage --> MITRE RAG --> Severity Assessment

3. Analysis (Automatic)
   Silver Analysis --> OpenCTI --> MISP --> Attack Narrative

4. Response (Gated)
   Silver Response --> Policy Check --> Approval Gate
   Approval --> Slack/Teams --> Human Approval
   Approved --> N8N/Wazuh/Firewall --> Containment

5. Documentation (Automatic)
   Case Service --> TheHive --> Case Creation
   Audit Service --> HMAC Log --> Compliance
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **LangGraph over CrewAI** | Explicit state machine, auditable transitions |
| **Monorepo (cobalto)** | Unified context for AI coding agents |
| **Groq Llama for triage** | $0.003/1K tokens, 10x cost savings |
| **HMAC audit chain** | Tamper detection, compliance |
| **5-layer context** | Separation of concerns, testability |

## Multi-Tenant Isolation

```
EKS Cluster
├── cobalto-system (shared services)
├── cobalto-acme-corp (tenant)
│   ├── Network Policies (default-deny)
│   ├── Resource Quotas (CPU/Memory)
│   └── Pod Security (restricted)
├── cobalto-global-bank (tenant)
│   ├── Network Policies
│   ├── Resource Quotas
│   └── Pod Security
└── monitoring (observability)
```

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/webhook/wazuh` | POST | Wazuh alert ingestion |
| `/webhook/generic` | POST | Generic SIEM webhook |
| `/webhook/n8n` | POST | n8n callback |
| `/agent/triage` | POST | Triage alert |
| `/agent/analyze-deep` | POST | Deep analysis |
| `/agent/threat-intel` | POST | Threat intel lookup |
| `/agent/response` | POST | Generate response |
| `/mcp/*` | various | MCP Bridge endpoints |

## Documentation

- [Context Engine](context-engine.md) - 5-layer model
- [Silver Agents](silver-agents.md) - Agent catalog
- [Supervisor](supervisor.md) - OSCAR framework
- [Services](services.md) - Approval, Audit, Case
- [Playbook Engine](playbook-engine.md) - YAML DSL
- [Infrastructure](infrastructure.md) - EKS, Terraform
