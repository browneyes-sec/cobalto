# Cobalto

**Agentic SOC/MDR Open Source Platform**

Cobalto is a multi-agent AI system for autonomous threat detection, investigation, and automated response. Built on LangGraph, Wazuh, OpenCTI, and TheHive for enterprise-grade security operations.

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
   |  Semantic | Operational | Intelligence | Policy | Memory  |
   +----------------------------------------------------+
           |                   |                   |
           v                   v                   v
   +----------------+  +----------------+  +----------------+
   |   APPROVAL     |  |    AUDIT       |  |    CASE        |
   |   SERVICE      |  |    SERVICE     |  |    SERVICE     |
   +----------------+  +----------------+  +----------------+
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

### Send First Alert

```bash
curl -X POST http://localhost:8000/webhook/wazuh \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-001",
    "alert": {
      "rule_id": 5712,
      "rule_level": 8,
      "rule_description": "Brute force attack detected",
      "srcip": "203.0.113.45",
      "dstip": "192.168.1.100"
    },
    "source": "wazuh"
  }'
```

### Python Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/unit/ -v
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture/README.md) | System overview and design |
| [Context Engine](docs/architecture/context-engine.md) | 5-layer context model |
| [Silver Agents](docs/architecture/silver-agents.md) | Agent catalog and tools |
| [Supervisor](docs/architecture/supervisor.md) | OSCAR framework |
| [Services](docs/architecture/services.md) | Approval, Audit, Case |
| [Playbook Engine](docs/architecture/playbook-engine.md) | YAML DSL and versioning |
| [Infrastructure](docs/architecture/infrastructure.md) | EKS, Terraform, Helm |
| [API Reference](docs/api/openapi.yaml) | OpenAPI specification |
| [Deployment](docs/runbooks/deployment.md) | Deployment procedures |
| [Incident Response](docs/runbooks/incident-response.md) | IR procedures |
| [Load Testing](docs/runbooks/load-testing.md) | Performance testing |
| [Atomic Red Team](docs/runbooks/atomic-red-team.md) | ATT&CK validation |
| [Getting Started](docs/development/getting-started.md) | Quick start guide |
| [Testing](docs/development/testing.md) | Test suite guide |
| [Contributing](docs/development/contributing.md) | Contribution guide |
| [Changelog](CHANGELOG.md) | Version history |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/webhook/wazuh` | POST | Wazuh alert ingestion |
| `/webhook/generic` | POST | Generic SIEM webhook |
| `/webhook/n8n` | POST | n8n callback |
| `/agent/analyze` | POST | Analyze alert with supervisor |
| `/agent/triage` | POST | Triage alert |
| `/agent/analyze-deep` | POST | Deep analysis |
| `/agent/threat-intel` | POST | Threat intel lookup |
| `/agent/response` | POST | Generate response actions |

## Testing

```bash
# Run all tests (206+ tests)
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=frameworks --cov-report=html

# Run load tests
python -c "from tests.load.load_test import run_load_test; import asyncio; asyncio.run(run_load_test())"

# Run Atomic Red Team validation
python -c "from tests.atomic_runner import run_atomic_validation; import asyncio; asyncio.run(run_atomic_validation())"
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [Contributing Guide](docs/development/contributing.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/browneyes-sec/cobalto/issues)
- **Discussions**: [GitHub Discussions](https://github.com/browneyes-sec/cobalto/discussions)

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
