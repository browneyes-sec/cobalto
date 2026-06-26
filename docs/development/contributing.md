# Contributing Guide

## Welcome

Thank you for contributing to Cobalto! This guide explains how to get started.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn

## Getting Started

### 1. Fork Repository

Fork on GitHub, then clone:

```bash
git clone https://github.com/your-username/cobalto.git
cd cobalto
```

### 2. Set Up Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Start local stack
docker compose up -d
```

### 3. Create Branch

```bash
git checkout -b feature/your-feature
```

## Development Workflow

### Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for public functions
- Keep functions focused (< 50 lines)

### Example

```python
from typing import Optional, Dict, Any

def enrich_alert(
    alert_id: str,
    alert_data: Dict[str, Any],
    timeout: Optional[int] = 30,
) -> Dict[str, Any]:
    """
    Enrich alert with external threat intelligence.

    Args:
        alert_id: Unique alert identifier
        alert_data: Raw alert data
        timeout: Request timeout in seconds

    Returns:
        Enriched alert data with threat intelligence

    Raises:
        TimeoutError: If enrichment exceeds timeout
    """
    # Implementation
    ...
```

### Testing

Run tests before submitting:

```bash
# Unit tests
python -m pytest tests/unit/ -v

# Specific component
python -m pytest tests/unit/agent/ -v
```

### Linting

```bash
# Check style
ruff check .

# Auto-fix
ruff check . --fix

# Format
ruff format .
```

## Pull Request Process

### 1. Update Documentation

- Add/update docstrings
- Update relevant docs in `docs/`
- Add CHANGELOG entry

### 2. Update Tests

- Add tests for new functionality
- Ensure all tests pass
- Maintain coverage

### 3. Commit Messages

Use conventional commits:

```
feat: add new enrichment tool
fix: resolve timeout issue
docs: update API documentation
test: add integration tests
refactor: simplify agent routing
```

### 4. Create PR

- Title: Concise description
- Body: What changed and why
- Link related issues

### 5. Code Review

- Address reviewer feedback
- Update PR as needed
- Merge when approved

## Architecture Guidelines

### Adding New Agent

1. Create agent in `services/langgraph/agents/`
2. Add tools in `frameworks/agent-sdk/src/cobalto/agent/`
3. Register in supervisor
4. Add tests
5. Update documentation

### Adding New Tool

1. Create tool function
2. Add to tool registry
3. Register with agent
4. Add tests

### Adding New Playbook

1. Create YAML in `playbooks/`
2. Follow schema in `docs/architecture/playbook-engine.md`
3. Test execution

## Documentation

### Types

| Type | Location | Purpose |
|------|----------|---------|
| Architecture | `docs/architecture/` | System design |
| API | `docs/api/openapi.yaml` | Endpoint specs |
| Runbooks | `docs/runbooks/` | Operational guides |
| Development | `docs/development/` | Contributor guides |

### Writing Docs

- Use Markdown
- Include code examples
- Keep concise
- Update when code changes

## Issues

### Bug Reports

Include:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details

### Feature Requests

Include:
- Use case
- Proposed solution
- Alternatives considered

## Release Process

1. Update CHANGELOG.md
2. Bump version in pyproject.toml
3. Create release tag
4. GitHub Actions deploys

## Questions?

- Open an issue
- Join Discord
- Email: team@cobalto.io
