# Load Testing Runbook

## Overview

Load testing validates Cobalto's performance under high alert volumes. Target: 10,000 alerts/hour with <2 minute MTTR.

## Prerequisites

- Cobalto running locally or on staging
- Python 3.11+
- Dependencies installed: `pip install httpx structlog`

## Quick Start

### Run Standard Load Test

```python
import asyncio
from tests.load.load_test import run_load_test

async def main():
    result = await run_load_test(
        cobalto_url="http://localhost:8000",
        target_rps=10000,      # 10K alerts/hour
        duration_seconds=300,  # 5 minutes
        concurrent_users=50,
    )
    print(f"MTTR: {result['analysis']['latency']['mttr_ms']:.0f}ms")
    print(f"Success Rate: {result['analysis']['summary']['success_rate']:.1f}%")

asyncio.run(main())
```

### Run Burst Test

```python
import asyncio
from tests.load.load_test import run_burst_test

async def main():
    result = await run_burst_test(
        cobalto_url="http://localhost:8000",
        burst_size=1000,
        burst_interval=60,
        num_bursts=5,
    )
    print(f"Total Alerts: {result['analysis']['summary']['total_alerts']}")

asyncio.run(main())
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `target_rps` | 10000 | Target alerts per hour |
| `duration_seconds` | 300 | Test duration |
| `concurrent_users` | 50 | Simulated users |
| `ramp_up_seconds` | 60 | User ramp-up time |
| `think_time_ms` | 100 | Delay between requests |

## Metrics

### Latency

| Metric | Target | Description |
|--------|--------|-------------|
| MTTR | < 120,000ms | Mean Time to Respond |
| P50 | < 60,000ms | 50th percentile |
| P95 | < 90,000ms | 95th percentile |
| P99 | < 120,000ms | 99th percentile |

### Throughput

| Metric | Target | Description |
|--------|--------|-------------|
| Actual RPS | >= 95% of target | Requests per second |
| Success Rate | >= 99% | Successful responses |

### SLA Compliance

| Metric | Target | Description |
|--------|--------|-------------|
| SLA Compliance | >= 95% | Alerts processed within MTTR target |

## Interpreting Results

### Sample Output

```json
{
  "summary": {
    "total_alerts": 1389,
    "success_rate": 99.8,
    "actual_rps": 2.78,
    "duration_seconds": 300
  },
  "latency": {
    "mttr_ms": 45000,
    "p50_ms": 35000,
    "p95_ms": 85000,
    "p99_ms": 115000
  },
  "sla": {
    "mttr_target_ms": 120000,
    "sla_compliance_percent": 98.5
  }
}
```

### Pass Criteria

- [ ] MTTR < 120,000ms (2 minutes)
- [ ] Success Rate >= 99%
- [ ] P95 < 90,000ms
- [ ] SLA Compliance >= 95%

## Troubleshooting

### High MTTR

1. Check Silver agent response times
2. Verify Redis connection (cache misses)
3. Check LLM API latency (Groq/OpenAI)
4. Scale Silver agents horizontally

### Low Success Rate

1. Check webhook endpoint health
2. Verify database connections
3. Review error logs for timeouts
4. Check rate limiting configuration

### Low Throughput

1. Increase concurrent users
2. Check network latency
3. Verify load balancer configuration
4. Scale infrastructure

## CI/CD Integration

```yaml
# .github/workflows/load-test.yml
name: Load Test
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  load-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install httpx structlog
      - run: python -m pytest tests/test_performance.py -v
```
