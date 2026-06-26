# Local Development Setup

## Prerequisites

| Tool         | Version   | Purpose                        | Install Link                                    |
|--------------|-----------|--------------------------------|-------------------------------------------------|
| Docker       | 24.0+     | Container runtime              | https://docs.docker.com/get-docker/             |
| Docker Compose | 2.20+  | Multi-container orchestration  | https://docs.docker.com/compose/install/        |
| Python       | 3.12+     | Agent development              | https://www.python.org/downloads/               |
| Node.js      | 20+       | Frontend tooling               | https://nodejs.org/                             |
| Terraform    | 1.7+      | Infrastructure provisioning    | https://developer.hashicorp.com/terraform/install |
| kubectl      | 1.29+     | Kubernetes management          | https://kubernetes.io/docs/tasks/tools/         |
| Helm         | 3.14+     | Package management             | https://helm.sh/docs/intro/install/             |
| uv           | 0.4+      | Python package management      | https://docs.astral.sh/uv/getting-started/install/ |
| just         | 1.35+     | Command runner                 | https://github.com/casey/just#installation      |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/cobalto/soc-platform.git
cd soc-platform

# Copy environment template
cp .env.example .env

# Start all services
docker compose up -d

# Verify services are running
docker compose ps

# Run database migrations
docker compose exec langgraph-agent uv run alembic upgrade head

# Seed test data
docker compose exec langgraph-agent uv run python -m scripts.seed_data

# Open n8n UI
open http://localhost:5678

# Open Grafana
open http://localhost:3000

# Open TheHive
open http://localhost:9000
```

## Environment Variables

Required in `.env`:

```bash
# Database
POSTGRES_USER=cobalto
POSTGRES_PASSWORD=changeme-local
POSTGRES_DB=cobalto

# Qdrant
QDRANT_URL=http://qdrant:6333

# Elasticsearch
ELASTICSEARCH_URL=http://elasticsearch:9200

# Vault (dev mode)
VAULT_ADDR=http://vault:8200
VAULT_DEV_ROOT_TOKEN_ID=root-token-dev

# n8n
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=changeme-local

# TheHive
THEHIVE_URL=http://thehive:9000
THEHIVE_API_KEY=changeme

# OpenCTI
OPENCTI_URL=http://opencti:4000
OPENCTI_API_KEY=changeme

# Cortex
CORTEX_URL=http://cortex:9001
CORTEX_API_KEY=changeme

# Slack (for notifications)
SLACK_BOT_TOKEN=xoxb-changeme
SLACK_SIGNING_SECRET=changeme

# External APIs (optional for local dev)
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
```

## Docker Compose Services

| Service         | Port  | URL                                    |
|-----------------|-------|----------------------------------------|
| langgraph-agent | 8080  | http://localhost:8080                  |
| n8n             | 5678  | http://localhost:5678                  |
| orchestrator    | 8000  | http://localhost:8000                  |
| thehive         | 9000  | http://localhost:9000                  |
| cortex          | 9001  | http://localhost:9001                  |
| opencti         | 4000  | http://localhost:4000                  |
| qdrant          | 6333  | http://localhost:6333/dashboard        |
| elasticsearch   | 9200  | http://localhost:9200                  |
| postgresql      | 5432  | localhost:5432                         |
| redis           | 6379  | localhost:6379                         |
| vault           | 8200  | http://localhost:8200                  |
| grafana         | 3000  | http://localhost:3000                  |
| prometheus      | 9090  | http://localhost:9090                  |
| minio           | 9000  | http://localhost:9001 (console)        |

## Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=services/langgraph-agent --cov-report=html

# Run specific test file
uv run pytest tests/test_agent.py -v

# Run integration tests (requires running services)
uv run pytest tests/integration/ -v --timeout=60

# Run linter
uv run ruff check services/langgraph-agent/

# Run type checker
uv run mypy services/langgraph-agent/

# Format code
uv run ruff format services/langgraph-agent/
```

## IDE Setup

### VS Code

Install extensions:
- Python (ms-python.python)
- Pylance (ms-python.vscode-pylance)
- Docker (ms-azuretools.vscode-docker)
- Kubernetes (ms-kubernetes-tools.vscode-kubernetes-tools)
- HashiCorp Terraform (hashicorp.terraform)
- Mermaid Preview (bierner.markdown-mermaid)

Recommended `settings.json`:

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.formatting.provider": "none",
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true
  },
  "files.exclude": {
    "**/__pycache__": true,
    "**/.pytest_cache": true,
    "**/node_modules": true
  }
}
```

### PyCharm

1. Open project root as Python project
2. Set interpreter to `.venv/bin/python`
3. Enable Ruff as external linter
4. Configure Docker Compose as deployment target

## Local Kubernetes (Optional)

For testing Kubernetes manifests locally:

```bash
# Start local cluster with kind
kind create cluster --name cobalto-local

# Apply kustomize overlays
kubectl apply -k deployments/kubernetes/overlays/local/

# Port-forward services
kubectl port-forward -n cobalto-core svc/langgraph-agent 8080:8080
kubectl port-forward -n cobalto-system svc/grafana 3000:3000

# Teardown
kind delete cluster --name cobalto-local
```

## Troubleshooting

| Issue                            | Fix                                                  |
|----------------------------------|------------------------------------------------------|
| Port already in use               | `lsof -i :<port>` to find and kill the process      |
| Docker permission denied          | `sudo usermod -aG docker $USER` then relogin        |
| Vault dev token expired           | Restart vault: `docker compose restart vault`        |
| Qdrant OOM                        | Increase memory in docker-compose.yml                |
| n8n workflows not triggering      | Check webhook URLs match localhost                   |
| Database connection refused        | Wait for PostgreSQL to be healthy, then retry        |
