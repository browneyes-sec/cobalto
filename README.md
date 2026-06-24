# Cobalto

**Agentic SOC/MDR Open Source Platform**

Cobalto is a multi-agent AI system for autonomous threat detection, investigation, and automated response. Built on LangGraph, Wazuh, OpenCTI, and TheHive for enterprise-grade security operations.

```
┌─────────────────────────────────────────────────────────────────┐
│                    COBALTO ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Wazuh    │  │ OpenCTI  │  │ TheHive  │  │ Cortex   │       │
│  │ SIEM/XDR │  │ Threat   │  │ Case Mgmt│  │ Enrich   │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │              │              │
│       └──────────────┴──────┬───────┴──────────────┘              │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │   n8n SOAR      │                          │
│                    │  Workflow Engine │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │  LangGraph AI   │                          │
│                    │  Agent Service  │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│       ┌─────────────────────┼─────────────────────┐            │
│       │                     │                     │            │
│  ┌────▼─────┐  ┌────────────▼──┐  ┌──────────────▼┐           │
│  │ Triage   │  │ Analysis      │  │ Response      │           │
│  │ Agent    │──▶ Agent         │──▶ Agent         │           │
│  └──────────┘  └───────────────┘  └───────────────┘           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- AWS CLI (for production deployment)
- kubectl & Helm (for Kubernetes deployment)

### Local Development

```bash
# Clone the repository
git clone https://github.com/browneyes-sec/cobalto.git
cd cobalto

# Start all services
docker compose up -d

# Access services
# - n8n SOAR:        http://localhost:5678
# - TheHive:         http://localhost:9000
# - OpenCTI:         http://localhost:4000
# - Grafana:         http://localhost:3000
# - LangGraph API:   http://localhost:8001
# - Wazuh Dashboard: http://localhost:5601
```

### Python Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e ".[dev,agent,soar,intel,vector]"

# Run tests
pytest tests/ -v

# Run linting
ruff check .
ruff format .

# Run type checking
mypy frameworks/ services/ --ignore-missing-imports
```

## Architecture

### Layer Architecture

| Layer | Concept | Ownership | Description |
|-------|---------|-----------|-------------|
| Service | MDR | Cobalt | Managed detection & response for multiple customers |
| Function | SOC | Cobalt | Central security function: monitoring, hunting, compliance |
| Platform | Agentic SOAR | Magenta | Multi-tenant automation engine (agents, playbooks, integrations) |
| Agents | Silver Guards | Magenta | Specialized agents: triage, analysis, hunting, response, documentation |

### C4 System Context

```
┌─────────────────────────────────────────────────────────────────┐
│                      System Context                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐                    ┌──────────────────┐          │
│  │   SOC    │                    │  Agentic SOC     │          │
│  │ Analyst  │◄──────────────────▶│  Platform        │          │
│  └──────────┘                    └──────────────────┘          │
│                                           ▲                     │
│       ┌───────────────────────────────────┤                     │
│       │                                   │                     │
│  ┌────▼────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Endpts  │  │  Cloud   │  │ Network  │  │ Identity │       │
│  │ Wazuh   │  │ AWS/GCP  │  │ Suricata │  │ AD/Okta  │       │
│  └─────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Container Architecture

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Wazuh SIEM** | Docker/EKS | Log collection, rule-based detection, active response |
| **OpenCTI** | Docker/EKS | STIX2 threat graph, TIP, MITRE ATT&CK, IOC management |
| **TheHive 5.x** | Docker/EKS | Case management, analyst workspace, incident lifecycle |
| **Cortex** | Docker/EKS | Observable enrichment (VirusTotal, AbuseIPDB, Shodan) |
| **n8n SOAR** | Docker/EKS | Low-code workflow automation, alert routing, playbook orchestration |
| **LangGraph** | Python FastAPI | Multi-agent AI orchestration: Triage, Analysis, Response, ThreatHunt, Documentation |
| **Qdrant** | Docker/EKS | MITRE ATT&CK embeddings, RAG knowledge base |
| **Elasticsearch** | EKS StatefulSet | Log indexing, full-text search, aggregation |
| **Grafana** | EKS Pod | SOC KPI dashboards, agent performance, cost tracking |
| **Vault** | EKS Pod | Secrets management, dynamic credentials, API key rotation |

### Agent Flow

```
Alert Ingestion → Schema Validation → Supervisor → Triage Agent
                                                      │
                                                      ▼
                                              MITRE Mapping (RAG)
                                                      │
                                                      ▼
                                              Severity Decision
                                              ┌─────┼─────┐
                                              ▼     ▼     ▼
                                          HIGH  MEDIUM  LOW
                                            │     │     │
                                            ▼     ▼     ▼
                                        Analysis  Threat  Doc
                                        Agent    Intel   Agent
                                            │     Agent
                                            ▼     │
                                        Response  ▼
                                        Agent  Correlation
                                            │
                                            ▼
                                    Human Approval (Slack)
                                            │
                                    ┌───────┴───────┐
                                    ▼               ▼
                                APPROVE          REJECT
                                    │               │
                                    ▼               ▼
                            Containment      Re-evaluate
                            Execution
                                    │
                                    ▼
                            Documentation
                            & Case Update
```

## Frameworks

### Core Framework (`frameworks/core/`)

| Module | Purpose |
|--------|---------|
| `config.py` | Pydantic settings with env vars, AWS Parameter Store |
| `logging.py` | Structured JSON logging with structlog |
| `metrics.py` | Prometheus metrics collection |
| `tracing.py` | OpenTelemetry distributed tracing |
| `secrets.py` | HashiCorp Vault integration |
| `health.py` | Kubernetes readiness/liveness probes |

### Agent SDK (`frameworks/agent-sdk/`)

| Module | Purpose |
|--------|---------|
| `base_agent.py` | Abstract base class for all agents |
| `state.py` | Typed state definitions for LangGraph |
| `tools.py` | Tool registry and base tool class |
| `memory.py` | Short-term (Redis) + Long-term (Qdrant) memory |
| `workflow.py` | LangGraph workflow builder |
| `supervisor.py` | Agent orchestration and routing |
| `prompts.py` | Prompt templates and versioning |

### SOAR SDK (`frameworks/soar-sdk/`)

| Module | Purpose |
|--------|---------|
| `workflow_builder.py` | n8n workflow definition builder |
| `webhook_handler.py` | Alert ingestion with schema validation |
| `playbook.py` | Automated response playbook engine |
| `integrations.py` | Wazuh, TheHive, Slack, Cortex, OpenCTI clients |

### Intel SDK (`frameworks/intel-sdk/`)

| Module | Purpose |
|--------|---------|
| `graphql_client.py` | OpenCTI GraphQL API client |
| `stix2_mapper.py` | Internal data → STIX2 conversion |
| `enrichment.py` | Multi-source enrichment pipeline |
| `mitre.py` | MITRE ATT&CK mapping with RAG |

### Vector SDK (`frameworks/vector-sdk/`)

| Module | Purpose |
|--------|---------|
| `embedder.py` | OpenAI/Sentence-transformers embeddings |
| `retriever.py` | Hybrid vector + keyword search |
| `collections.py` | Qdrant collection management |

## Deployment

### Local (Docker Compose)

```bash
docker compose up -d
```

### Staging (AWS EKS)

```bash
# Configure AWS credentials
aws configure

# Deploy infrastructure
cd infra/terraform/environments/staging
terraform init
terraform apply

# Deploy applications
helm upgrade --install cobalto infra/kubernetes/charts/cobalto \
  --namespace staging \
  --create-namespace \
  --values infra/kubernetes/charts/cobalto/values-staging.yaml
```

### Production (AWS EKS)

```bash
# Tag a release
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions will automatically:
# 1. Run tests
# 2. Build Docker images
# 3. Deploy to staging
# 4. Run smoke tests
# 5. Deploy to production (with approval)
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `REDIS_URL` | Yes | - | Redis connection string |
| `WAZUH_PASSWORD` | Yes | - | Wazuh API password |
| `OPENCTI_TOKEN` | Yes | - | OpenCTI API token |
| `THEHIVE_TOKEN` | Yes | - | TheHive API token |
| `N8N_API_KEY` | Yes | - | n8n API key |
| `LANGGRAPH_API_KEY` | Yes | - | LangGraph API key |
| `JWT_SECRET_KEY` | Yes | - | JWT signing key |
| `SLACK_BOT_TOKEN` | No | - | Slack bot token |
| `VIRUSTOTAL_API_KEY` | No | - | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | No | - | AbuseIPDB API key |

### Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `ENABLE_MITRE_MAPPING` | `true` | Enable MITRE ATT&CK mapping |
| `ENABLE_THREAT_HUNT` | `false` | Enable Threat Hunt Agent |
| `ENABLE_DOCUMENTATION_AGENT` | `false` | Enable Documentation Agent |
| `ENABLE_AUTO_RESPONSE` | `false` | Enable automated response |
| `ENABLE_MULTI_TENANT` | `false` | Enable multi-tenancy |

## API Endpoints

### LangGraph Agent Service

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/agent/analyze` | POST | Analyze alert with supervisor |
| `/agent/run` | POST | Run specific agent |
| `/agent/triage` | POST | Triage alert |
| `/agent/analyze-deep` | POST | Deep analysis |
| `/agent/threat-intel` | POST | Threat intel lookup |
| `/agent/response` | POST | Generate response actions |

### n8n SOAR

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook/{source}` | POST | Ingest alert from source |
| `/webhook` | POST | Generic alert ingestion |

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run unit tests only
pytest tests/unit/ -v

# Run integration tests only
pytest tests/integration/ -v

# Run with coverage
pytest tests/ --cov=frameworks --cov-report=html

# Run specific test file
pytest tests/unit/agent/test_base_agent.py -v
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- **Linting**: Ruff
- **Formatting**: Ruff format
- **Type Checking**: MyPy
- **Testing**: Pytest
- **Commit Messages**: Conventional Commits

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [docs.cobalto.io](https://docs.cobalto.io)
- **Issues**: [GitHub Issues](https://github.com/browneyes-sec/cobalto/issues)
- **Discussions**: [GitHub Discussions](https://github.com/browneyes-sec/cobalto/discussions)
- **Security**: [SECURITY.md](SECURITY.md)
