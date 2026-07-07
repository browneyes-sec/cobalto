# Performance Domain — Controls PE-01 through PE-12

**Steady-State Hypothesis**: The platform processes alerts with <2s p99 agent latency, <500ms p99 tool latency, and <50% CPU/memory under baseline load.

## Controls

| ID | Control | Metric | Threshold | Procedure |
|----|---------|--------|-----------|-----------|
| PE-01 | Agent execution latency p50 | `cobalto_agent_latency_seconds{quantile="0.5"}` | ≤ 1.0s | performance-benchmark.sh |
| PE-02 | Agent execution latency p95 | `cobalto_agent_latency_seconds{quantile="0.95"}` | ≤ 2.0s | performance-benchmark.sh |
| PE-03 | Agent execution latency p99 | `cobalto_agent_latency_seconds{quantile="0.99"}` | ≤ 5.0s | performance-benchmark.sh |
| PE-04 | Tool call latency p50 | `cobalto_tool_latency_seconds{quantile="0.5"}` | ≤ 200ms | performance-benchmark.sh |
| PE-05 | Tool call latency p95 | `cobalto_tool_latency_seconds{quantile="0.95"}` | ≤ 500ms | performance-benchmark.sh |
| PE-06 | Tool call latency p99 | `cobalto_tool_latency_seconds{quantile="0.99"}` | ≤ 2.0s | performance-benchmark.sh |
| PE-07 | Alert ingestion throughput | `rate(cobalto_alerts_received_total[1m])` | ≥ 10/min | performance-benchmark.sh |
| PE-08 | HTTP request latency p95 | API response time | ≤ 500ms | performance-benchmark.sh |
| PE-09 | Memory usage per agent pod | `process_resident_memory_bytes` | ≤ 512MB | performance-benchmark.sh |
| PE-10 | CPU usage per agent pod | `process_cpu_seconds_total` | ≤ 1.0 core | performance-benchmark.sh |
| PE-11 | Concurrent alert processing | Alert burst test | ≥ 50 concurrent | performance-benchmark.sh |
| PE-12 | End-to-end alert → report time | Full pipeline duration | ≤ 10s | performance-benchmark.sh |

## Steady-State Verification
- Verify baseline metrics before load test (idle state)
- Apply load at 10 alerts/min for 2 minutes
- Measure metrics during steady load
- Verify recovery to baseline after load stops
