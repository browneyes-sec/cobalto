# Atomic Red Team Validation Runbook

## Overview

Validates Cobalto's detection and response capabilities using Atomic Red Team tests against MITRE ATT&CK techniques.

## Supported Techniques

| Technique | Name | Platform | Tests |
|-----------|------|----------|-------|
| T1110 | Brute Force | Windows | 1 |
| T1059 | Command and Scripting Interpreter | Windows | 1 |
| T1053 | Scheduled Task/Job | Windows | 1 |
| T1547 | Boot or Logon Autostart Execution | Windows | 1 |
| T1071 | Application Layer Protocol | Windows/Linux/macOS | 1 |
| T1105 | Ingress Tool Transfer | Windows | 1 |
| T1027 | Obfuscated Files or Information | Windows | 1 |
| T1055 | Process Injection | Windows | 1 |
| T1082 | System Information Discovery | Windows | 1 |
| T1018 | Remote System Discovery | Windows/Linux | 1 |

## Quick Start

### Run All Tests (Simulated)

```python
import asyncio
from tests.atomic_runner import run_atomic_validation

async def main():
    result = await run_atomic_validation(
        cobalto_url="http://localhost:8000",
        techniques=["T1110", "T1059", "T1053"],
        simulate=True,  # Generate synthetic alerts
    )
    print(f"Total Tests: {result['total_tests']}")
    print(f"Passed: {result['passed']}")
    print(f"Failed: {result['failed']}")

asyncio.run(main())
```

### Run Single Technique

```python
import asyncio
from tests.atomic_runner import AtomicRedTeamRunner

async def main():
    runner = AtomicRedTeamRunner(
        cobalto_api_url="http://localhost:8000",
    )
    results = await runner.run_technique_suite(
        "T1110",  # Brute Force
        simulate=True,
    )
    for result in results:
        print(f"{result.test_id}: {result.status.value}")

asyncio.run(main())
```

## Test Modes

### Simulated Mode (Recommended)

Generates synthetic alerts without executing actual attack commands.

```python
await run_atomic_validation(simulate=True)
```

### Live Mode (Use with Caution)

Executes actual Atomic Red Team commands. Only use in isolated test environments.

```python
await run_atomic_validation(simulate=False)
```

## Coverage Report

```python
from tests.atomic_runner import AtomicRedTeamRunner

runner = AtomicRedTeamRunner()
# ... run tests ...
report = runner.get_coverage_report()

print(f"Fully Covered: {report['fully_covered']}")
print(f"Partially Covered: {report['partially_covered']}")
print(f"Not Detected: {report['not_detected']}")
```

### Sample Output

```json
{
  "timestamp": "2026-06-25T19:00:00Z",
  "total_techniques": 10,
  "fully_covered": 8,
  "partially_covered": 1,
  "not_detected": 1,
  "avg_detection_time_ms": 2500,
  "techniques": [
    {
      "technique_id": "T1110",
      "name": "Brute Force",
      "status": "fully_covered",
      "tests_executed": 1,
      "alerts_detected": 1,
      "avg_detection_time_ms": 1800
    }
  ]
}
```

## Pass Criteria

| Metric | Target |
|--------|--------|
| Fully Covered | >= 80% of techniques |
| Detection Rate | >= 90% of tests |
| Avg Detection Time | < 5000ms |

## Adding New Tests

### 1. Define Test

Edit `tests/atomic_runner.py`:

```python
COMMON_ATOMIC_TESTS["T1234"] = [
    AtomicTest(
        test_id="T1234-1",
        name="Test Name",
        description="Test description",
        technique_id="T1234",
        executor="command_prompt",
        supported_platforms=["windows"],
        commands=["your-command-here"],
        cleanup_commands=["cleanup-command"],
    ),
]
```

### 2. Add Alert Mapping

```python
technique_alerts["T1234"] = {
    "rule_id": 5712,
    "rule_level": 7,
    "rule_description": "Description for detection",
    "rule_groups": "your,groups",
}
```

### 3. Add Tactic Mapping

```python
tactic_map["T1234"] = "execution"  # MITRE tactic
```

## Troubleshooting

### Tests Not Detected

1. Check webhook endpoint is receiving alerts
2. Verify alert format matches expected schema
3. Review Silver Triage agent logs
4. Check MITRE RAG is loaded

### High Detection Time

1. Check Qdrant vector DB performance
2. Verify OpenCTI connection
3. Review LLM API latency
4. Check Redis cache hits

## CI/CD Integration

```yaml
# .github/workflows/atomic-validation.yml
name: Atomic Red Team Validation
on:
  schedule:
    - cron: '0 3 * * 1'  # Weekly on Monday

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install httpx structlog
      - run: python -c "
          import asyncio;
          from tests.atomic_runner import run_atomic_validation;
          asyncio.run(run_atomic_validation(simulate=True))
        "
```
