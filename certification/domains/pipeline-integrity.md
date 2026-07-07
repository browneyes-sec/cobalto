# Pipeline Integrity Domain — Controls PI-01 through PI-08

**Steady-State Hypothesis**: Every alert received via `/agent/analyze` or `/webhook/wazuh` produces a complete incident report with all pipeline stages executed.

## Controls

| ID | Control | Verification | Procedure |
|----|---------|-------------|-----------|
| PI-01 | Alert ingestion accepts valid payload | HTTP 200 with incident_id | pipeline-integrity-test.sh |
| PI-02 | Alert ingestion rejects malformed payload | HTTP 422 with validation error | pipeline-integrity-test.sh |
| PI-03 | Agent triage produces severity classification | severity field non-empty in response | pipeline-integrity-test.sh |
| PI-04 | Agent pipeline produces incident report | final_report field contains markdown | pipeline-integrity-test.sh |
| PI-05 | Prometheus metrics increment on alert | `cobalto_alerts_received_total` increases by 1 | pipeline-integrity-test.sh |
| PI-06 | Audit log captures alert reception | Audit entry with action "alert_received" exists | pipeline-integrity-test.sh |
| PI-07 | Webhook normalizes n8n-wrapped Wazuh alerts | `/webhook/wazuh` returns same schema as `/agent/analyze` | pipeline-integrity-test.sh |
| PI-08 | Health endpoint returns 200 | `GET /health` responds within 1s | pipeline-integrity-test.sh |

## Steady-State Verification
- Service is running with all dependencies (postgres, redis)
- Prometheus metrics endpoint is accessible
- Audit logger is accepting entries
