# Testing Guide

## Overview

Cobalto uses pytest for testing with 206+ tests covering all components.

## Test Structure

```
tests/
├── unit/
│   ├── agent/
│   │   ├── test_base_agent.py
│   │   ├── test_silver_triage.py
│   │   ├── test_silver_analysis.py
│   │   ├── test_silver_response.py
│   │   ├── test_supervisor.py
│   │   └── test_services.py
│   ├── soar/
│   │   ├── test_workflow.py
│   │   └── test_playbook_enhanced.py
│   ├── core/
│   │   └── test_config.py
│   ├── intel/
│   │   └── test_stix2.py
│   └── mcp/
│       ├── test_protocol.py
│       ├── test_server.py
│       └── test_tools.py
├── integration/
│   └── test_agents.py
├── load/
│   └── load_test.py
├── atomic_runner.py
└── test_performance.py
```

## Running Tests

### All Tests

```bash
python -m pytest tests/unit/ -v
```

### Specific Test File

```bash
python -m pytest tests/unit/agent/test_silver_triage.py -v
```

### Specific Test Class

```bash
python -m pytest tests/unit/agent/test_silver_triage.py::TestSilverTriageAgent -v
```

### Specific Test

```bash
python -m pytest tests/unit/agent/test_silver_triage.py::TestSilverTriageAgent::test_triage_alert -v
```

### With Coverage

```bash
python -m pytest tests/unit/ --cov=cobalto --cov-report=html
```

### Load Tests

```bash
python -m pytest tests/test_performance.py -v
```

## Test Categories

### Unit Tests

Fast, isolated tests for individual components.

```python
# tests/unit/agent/test_silver_triage.py
import pytest
from services.langgraph.agents.triage import SilverTriageAgent

class TestSilverTriageAgent:
    def test_initialization(self):
        agent = SilverTriageAgent()
        assert agent is not None

    @pytest.mark.asyncio
    async def test_triage_alert(self):
        agent = SilverTriageAgent()
        result = await agent.run({
            "alert_id": "test-001",
            "alert": {"rule_level": 8},
        })
        assert result.status == "success"
```

### Integration Tests

Tests that verify component interactions.

```python
# tests/integration/test_agents.py
import pytest

@pytest.mark.integration
class TestAgentIntegration:
    @pytest.mark.asyncio
    async def test_full_pipeline(self):
        # Test complete alert processing pipeline
        ...
```

### Load Tests

Performance and stress testing.

```python
# tests/test_performance.py
import pytest

class TestLoadPerformance:
    def test_throughput(self):
        # Verify 10K alerts/hour capacity
        ...

    def test_mttr(self):
        # Verify <2 minute MTTR
        ...
```

## Writing Tests

### Test File Naming

- Pattern: `test_*.py`
- Example: `test_silver_triage.py`

### Test Class Naming

- Pattern: `Test*`
- Example: `TestSilverTriageAgent`

### Test Method Naming

- Pattern: `test_*`
- Example: `test_triage_alert`

### Async Tests

Use `@pytest.mark.asyncio` decorator:

```python
@pytest.mark.asyncio
async def test_async_operation():
    result = await some_async_function()
    assert result is not None
```

### Fixtures

```python
import pytest

@pytest.fixture
def sample_alert():
    return {
        "alert_id": "test-001",
        "rule_id": 5712,
        "rule_level": 8,
        "source_ip": "203.0.113.45",
    }

def test_alert_processing(sample_alert):
    assert sample_alert["rule_level"] == 8
```

### Mocking

```python
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_with_mock():
    with patch("httpx.AsyncClient") as mock_client:
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_client.return_value.__aenter__.return_value.post.return_value = mock_response

        result = await call_api()
        assert result is not None
```

## Test Environment

### Environment Variables

```bash
# Test mode
TESTING=1

# Mock endpoints (don't call real APIs)
MOCK_EXTERNAL_APIS=1
```

### Test Database

Tests use SQLite in-memory by default:

```python
# pytest.ini
[tool.pytest.ini_options]
asyncio_mode = "auto"
```

## CI/CD Integration

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: python -m pytest tests/unit/ -v --tb=short
```

## Debugging Tests

### Verbose Output

```bash
python -m pytest tests/unit/ -v -s
```

### Stop on First Failure

```bash
python -m pytest tests/unit/ -x
```

### Run Last Failed

```bash
python -m pytest tests/unit/ --lf
```

### Drop into Debugger

```bash
python -m pytest tests/unit/ -v --pdb
```

## Coverage Report

```bash
python -m pytest tests/unit/ --cov=cobalto --cov-report=term-missing
```

Output:

```
Name                                    Stmts   Miss  Cover
-----------------------------------------------------------
cobalto/agent/triage_tools.py             50      5    90%
cobalto/agent/analysis_tools.py           45      3    93%
cobalto/context/context_package.py        80      8    90%
-----------------------------------------------------------
TOTAL                                    500     50    90%
```
