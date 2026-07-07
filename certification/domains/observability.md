# Observability Domain — Controls OB-01 through OB-07

**Steady-State Hypothesis**: All platform components emit structured metrics, logs, and traces that are queryable within 30s of generation.

## Controls

| ID | Control | Verification | Procedure |
|----|---------|-------------|-----------|
| OB-01 | Prometheus metrics endpoint is accessible | `GET /metrics` returns HTTP 200 | performance-benchmark.sh |
| OB-02 | All 9 cobalto_* metric families are present | grep for each metric in /metrics output | performance-benchmark.sh |
| OB-03 | Metrics have correct label cardinality | Each metric has expected label keys | performance-benchmark.sh |
| OB-04 | Audit logs are structured JSON | Log entry parses as valid JSON | security-controls-test.sh |
| OB-05 | Prometheus can scrape agent metrics | Prometheus target shows "up" status | performance-benchmark.sh |
| OB-06 | Grafana dashboard renders panels | Dashboard API returns panel data | observability-check.sh |
| OB-07 | Service /health and /ready endpoints respond | Endpoints return 200 within 1s | pipeline-integrity-test.sh |

## Steady-State Verification
- Prometheus is running and configured to scrape langgraph-agent
- Grafana is running with provisioned datasource
- Agent service is running
