# Cobalto — Agentic SOC/MDR Platform

Open-source, AI-native Security Operations platform built on **Wazuh**, **OpenCTI**, **TheHive**, **n8n**, and **LangGraph** multi-agent orchestration.

> **"Cobalt BlueOps MDR — Agentic SOC platform powered by Magenta Silver Agents."**

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 4: PRESENTATION & GOVERNANCE                                      │
│  Cobalt Console (Next.js) │ Grafana Dashboards │ Human Approval (Slack) │
├─────────────────────────────────────────────────────────────────────────┤
│  LAYER 3: AGENT ORCHESTRATION (LangGraph / Silver Guard Agents)         │
│  Supervisor │ Triage │ Analysis │ Response │ ThreatHunt │ Documentation │
├─────────────────────────────────────────────────────────────────────────┤
│  LAYER 2: WORKFLOW AUTOMATION (n8n SOAR)                                │
│  Alert Routing │ Enrichment │ Response Approval │ Hunt Scheduling       │
├─────────────────────────────────────────────────────────────────────────┤
│  LAYER 1: DATA FOUNDATION                                                │
│  Wazuh SIEM │ OpenCTI (TIP) │ Cortex │ Qdrant (MITRE RAG) │ Vault     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Metrics

| Metric | Manual SOC | Cobalto Target |
|--------|-----------|----------------|
| MTTR (Mean Time to Respond) | 15–30 min | **< 2 min** |
| MTTD (Mean Time to Detect) | 4–8 hours | **< 5 min** |
| False Positive Rate | 40–60% | **< 10%** |
| Alerts/Analyst/Hour | ~10 | **200+** (AI-assisted) |
| Monthly Cost | $50K–$150K | **~$4,155** |

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/browneyes-sec/cobalto.git
cd cobalto
cp .env.example .env
# Edit .env with your AWS credentials and API keys

# 2. Bootstrap infrastructure (Terraform)
./scripts/bootstrap.sh dev

# 3. Deploy platform services (Kubernetes)
./scripts/deploy-platform.sh dev

# 4. Seed MITRE ATT&CK into Qdrant
kubectl apply -f kubernetes/langgraph/seed-mitre-job.yaml

# 5. Initialize TheHive + Cortex
./scripts/thehive-bootstrap/thehive-init.sh
./scripts/cortex-bootstrap/cortex-init.sh

# 6. Import n8n workflows
./scripts/n8n-init.sh
```

## Documentation

### Design Principles
- [Design Technology Principles](docs/dtp/design-principles.md) — 10 core axioms
- [Security Principles](docs/dtp/security-principles.md) — Security-by-default
- [AI Ethics for SOC](docs/dtp/ai-ethics-soc.md) — Human-in-the-loop governance
- [Cost Governance](docs/dtp/cost-governance.md) — Token budgets and optimization
- [Operational Principles](docs/dtp/operational-principles.md) — SLA and escalation

### Context
- [Business Context](docs/context/business-context.md) — Service model and value proposition
- [Domain Model](docs/context/domain-model.md) — Threat landscape and alert lifecycle
- [Regulatory Landscape](docs/context/regulatory-landscape.md) — SOC 2, PCI DSS, HIPAA, NIST
- [Stakeholder Map](docs/context/stakeholder-map.md) — RACI matrix and roles

### Architecture
- [Architecture Overview](docs/architecture/overview.md) — C4 diagrams and component stack
- [Service Architecture](docs/architecture/service-architecture/langgraph-agent.md) — Agent internals
- [Security Architecture](docs/architecture/security-architecture.md) — Defense in depth
- [Data Architecture](docs/architecture/data-architecture.md) — Data models and schemas
- [API Contracts](docs/architecture/api-contracts.md) — Endpoint specifications
- [Network Topology](docs/architecture/network-topology.md) — VPC and security groups
- [Integration Patterns](docs/architecture/service-architecture/integration-patterns.md) — Service communication

### Frameworks
- [LangGraph Patterns](docs/framework/langgraph-patterns.md) — State graph and routing
- [n8n Playbook Framework](docs/framework/n8n-playbook-framework.md) — Workflow patterns
- [Testing Strategy](docs/framework/testing-strategy.md) — Unit, integration, Atomic Red Team
- [Deployment Framework](docs/framework/deployment-framework.md) — GitOps and Kustomize

### ADRs
| ADR | Decision | Status |
|-----|----------|--------|
| [ADR-001](docs/architecture/adrs/ADR-001-langgraph.md) | LangGraph over CrewAI/AutoGen | Accepted |
| [ADR-002](docs/architecture/adrs/ADR-002-n8n.md) | n8n over Airflow/Shuffle | Accepted |
| [ADR-003](docs/architecture/adrs/ADR-003-opencti.md) | OpenCTI over MISP-only | Accepted |
| [ADR-004](docs/architecture/adrs/ADR-004-wazuh.md) | Wazuh over Elastic SIEM | Accepted |
| [ADR-005](docs/architecture/adrs/ADR-005-qdrant.md) | Qdrant for MITRE RAG | Accepted |
| [ADR-006](docs/architecture/adrs/ADR-006-thehive-cortex.md) | TheHive + Cortex | Accepted |
| [ADR-007](docs/architecture/adrs/ADR-007-vault.md) | HashiCorp Vault | Accepted |
| [ADR-008](docs/architecture/adrs/ADR-008-grafana.md) | Grafana + Prometheus | Accepted |
| [ADR-009](docs/architecture/adrs/ADR-009-kubernetes.md) | EKS + Kustomize + Flux | Accepted |

### Operations
- [Wazuh Runbook](docs/operations/runbook-wazuh.md)
- [LangGraph Runbook](docs/operations/runbook-langgraph.md)
- [n8n Runbook](docs/operations/runbook-n8n.md)
- [OpenCTI Runbook](docs/operations/runbook-opencti.md)
- [Qdrant Runbook](docs/operations/runbook-qdrant.md)
- [Elasticsearch Runbook](docs/operations/runbook-elasticsearch.md)
- [Vault Runbook](docs/operations/runbook-vault.md)

### Developer
- [Local Setup](docs/developer/local-setup.md)
- [Architecture Walkthrough](docs/developer/architecture-walkthrough.md)

## Technology Stack

| Layer | Component | Technology |
|-------|-----------|------------|
| **AI Agents** | Orchestration | LangGraph + LangChain |
| **LLM Backend** | Reasoning | OpenAI GPT-4o / Groq Llama 3.3 70B |
| **Vector Store** | MITRE RAG | Qdrant |
| **SIEM/XDR** | Detection | Wazuh 4.x |
| **Threat Intel** | Intelligence | OpenCTI + MISP |
| **Case Mgmt** | Investigations | TheHive 5.x |
| **Enrichment** | IOC Analysis | Cortex |
| **SOAR** | Automation | n8n |
| **Console** | UI | Next.js + React + TypeScript |
| **Secrets** | Key Mgmt | HashiCorp Vault |
| **Monitoring** | Observability | Grafana + Prometheus |
| **Infrastructure** | Orchestration | AWS EKS + Terraform |
| **CI/CD** | Pipeline | GitHub Actions + Flux CD |

## Cost Estimate (Monthly AWS)

| Component | Est. Cost |
|-----------|-----------|
| EKS (3× m6g.xlarge Graviton3) | ~$420 |
| OpenSearch (3-node r6g.large) | ~$550 |
| RDS PostgreSQL (db.t4g.medium Multi-AZ) | ~$110 |
| ElastiCache Redis (cache.t4g.medium) | ~$70 |
| Amazon MQ (mq.t3.micro) | ~$35 |
| S3 (5TB + Intelligent Tiering) | ~$120 |
| NAT + ALB + Security | ~$150 |
| **LLM API (OpenAI GPT-4o, 50K alerts/mo)** | ~$2,500 |
| **Total** | **~$4,155/mo** |

> vs. commercial SIEM/SOAR: $50K–$150K/mo — **90%+ cost reduction**

## License

Apache-2.0 — See [LICENSE](LICENSE)

---

*Built with purpose. Secured by design. Powered by AI agents with human control.*