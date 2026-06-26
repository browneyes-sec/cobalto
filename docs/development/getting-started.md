# Getting Started

## Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git
- AWS CLI (for production deployment)
- kubectl (for Kubernetes)

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/browneyes-sec/cobalto.git
cd cobalto
```

### 2. Start Local Stack

```bash
docker compose up -d
```

This starts 13 services:

| Service | URL | Credentials |
|---------|-----|-------------|
| LangGraph API | http://localhost:8000 | - |
| n8n | http://localhost:5678 | admin/admin123 |
| Grafana | http://localhost:3000 | admin/admin123 |
| Prometheus | http://localhost:9090 | - |
| OpenCTI | http://localhost:4000 | admin@cobalto.local / Admin123! |
| TheHive | http://localhost:9000 | admin@cobalto.local / secret |
| Cortex | http://localhost:9001 | - |
| Wazuh | https://localhost:55000 | admin / admin |

### 3. Set Up Python Environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 4. Verify Installation

```bash
# Health check
curl http://localhost:8000/health

# Run tests
python -m pytest tests/unit/ -v
```

### 5. Send First Alert

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

## Project Structure

```
cobalto/
├── frameworks/           # Core SDK packages
│   ├── core/            # Config, logging, metrics
│   ├── agent-sdk/       # Agent tools and services
│   ├── context-engine/  # 5-layer context model
│   ├── intel-sdk/       # Threat intelligence
│   ├── vector-sdk/      # Vector database
│   ├── soar-sdk/        # SOAR integrations
│   ├── mcp-bridge/      # MCP protocol bridge
│   └── testing/         # Test utilities
├── services/
│   └── langgraph/       # Agent orchestration service
├── playbooks/           # YAML response playbooks
├── tests/               # Test suite
├── infra/               # Infrastructure (Terraform, Helm)
├── docs/                # Documentation
└── docker-compose.yml   # Local development stack
```

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

Edit files in `frameworks/` or `services/`.

### 3. Run Tests

```bash
# Unit tests
python -m pytest tests/unit/ -v

# Specific test
python -m pytest tests/unit/agent/test_silver_triage.py -v
```

### 4. Commit & Push

```bash
git add .
git commit -m "feat: add new feature"
git push origin feature/my-feature
```

### 5. Create PR

Create pull request on GitHub.

## Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Key variables:

```bash
# LLM APIs
GROQ_API_KEY=your-groq-key
OPENAI_API_KEY=your-openai-key

# Integrations
OPENCTI_TOKEN=your-opencti-token
THEHIVE_TOKEN=your-thehive-token
SLACK_BOT_TOKEN=xoxb-...

# Database
DATABASE_URL=postgresql://cobalto:cobalto_local_dev@localhost:5432/cobalto
REDIS_URL=redis://localhost:6379
```

## IDE Setup

### VS Code

Install extensions:
- Python
- Pylance
- Docker
- Kubernetes

### PyCharm

1. Open project root
2. Set Python interpreter to `.venv`
3. Mark `frameworks/*/src` as Sources Root

## Next Steps

- Read [Architecture](../architecture/README.md)
- Review [API Documentation](../api/openapi.yaml)
- Check [Deployment Guide](../runbooks/deployment.md)
