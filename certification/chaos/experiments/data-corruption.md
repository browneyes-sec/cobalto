# Chaos Experiment: Data Corruption — Malformed Alert Injection

> **Domain:** Pipeline Integrity  
> **Blast Radius:** Pod (default)  
> **CI-Safe:** ✅  
> **Tool:** Custom Python fuzzer + k6

## Hypothesis

**Given** the LangGraph Agent validates inputs against a strict Pydantic schema with `additionalProperties: false`,  
**When** a malformed alert payload (extra fields, wrong types, missing required fields) is sent to POST /agent/analyze,  
**Then** the service returns HTTP 422 with a descriptive error message,  
**And** the audit log records the validation failure,  
**And** subsequent valid requests continue processing normally (no state corruption).

## Steady State

| Metric | Pre-Experiment | During | Post-Experiment |
|--------|---------------|--------|-----------------|
| Valid request success rate | 100% | 100% (valid reqs only) | 100% |
| Malformed request response | N/A | 422 | N/A |
| Audit log entries | normal | validation_failure events | normal |
| Service stability | healthy | healthy | healthy |

## Experiment Design

```yaml
kind: ChaosExperiment
metadata:
  name: malformed-alert-injection
  domain: pipeline-integrity
spec:
  duration: 120s
  interval: 5s
  target:
    app: langgraph-agent
    namespace: cobalto
  experiment:
    - action: http-chaos
      target: langgraph-agent
      fault: payload-corruption
      corruption_types:
        - extra_fields
        - missing_required
        - wrong_types
        - null_fields
        - oversized_strings
        - unicode_injection
        - control_characters
      percentage: 50
      duration: 60s
  steady_state:
    - metric: "valid_request_success_rate"
      threshold: "= 100%"
    - metric: "malformed_rejection_rate"
      threshold: "= 100% (422)"
    - metric: "service_health"
      threshold: "always healthy"
  rollback:
    method: "stop payload corruption"
    max_duration: 5s
```

## Procedure

```bash
#!/bin/bash
set -euo pipefail

echo "=== Data Corruption Experiment: Malformed Alerts ==="
echo "Sending corrupted payloads + valid interleaved payloads"

# 1. Generate malformed payloads
echo "--- Generating malformed payloads ---"

# Extra field (should be 422)
EXTRA_FIELD='{
  "alert_id": "CHAOS-EXTRA",
  "rule_id": 800300,
  "rule_description": "Extra field test",
  "alert_level": 1,
  "source_ip": "10.0.0.80",
  "dest_ip": "10.0.0.40",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos extra field test",
  "malicious_field": "injection"
}'

# Missing required field (should be 422)
MISSING_FIELD='{
  "alert_id": "CHAOS-MISSING",
  "rule_id": 800300,
  "rule_description": "Missing required test"
}'

# Wrong type (should be 422)
WRONG_TYPE='{
  "alert_id": "CHAOS-TYPE",
  "rule_id": "not-a-number",
  "rule_description": "Wrong type test",
  "alert_level": 1,
  "source_ip": "10.0.0.81",
  "dest_ip": "10.0.0.41",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos wrong type test"
}'

# Null fields (should be 422)
NULL_FIELDS='{
  "alert_id": "CHAOS-NULL",
  "rule_id": null,
  "rule_description": "Null field test",
  "alert_level": 1,
  "source_ip": null,
  "dest_ip": null,
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos null field test"
}'

# Control characters (should be 422 or sanitized)
CONTROL_CHARS='{
  "alert_id": "CHAOS-CTRL-'$'\x00\x01\x02'",
  "rule_id": 800300,
  "rule_description": "Control chars test",
  "alert_level": 1,
  "source_ip": "10.0.0.82",
  "dest_ip": "10.0.0.42",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos control chars '$'\x00\x7f\xff' test"
}'

# Oversized string (should be 422)
OVERSIZED=$(python3 -c "print('A' * 100000)")
OVERSIZED_FIELD='{
  "alert_id": "CHAOS-BIG",
  "rule_id": 800300,
  "rule_description": "'"$OVERSIZED"'",
  "alert_level": 1,
  "source_ip": "10.0.0.83",
  "dest_ip": "10.0.0.43",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos oversized test"
}'

# 2. Interleave valid + malformed requests
echo "--- Sending interleaved valid and malformed payloads ---"

send_payload() {
  local desc="$1"
  local payload="$2"
  local expected="$3"

  RESP=$(curl -s -X POST http://localhost:8000/agent/analyze \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    -w "\n%{http_code}")
  
  HTTP_CODE=$(echo "$RESP" | tail -1)
  
  if [ "$HTTP_CODE" = "$expected" ]; then
    echo "  ✅ $desc → $HTTP_CODE (expected $expected)"
  else
    echo "  ❌ $desc → $HTTP_CODE (expected $expected)"
    echo "     Payload: $(echo "$payload" | head -c 100)"
  fi
}

# Send valid payload first (baseline)
send_payload "Valid baseline" '{
  "alert_id": "CHAOS-VALID-1",
  "rule_id": 800300,
  "rule_description": "Valid baseline test",
  "alert_level": 1,
  "source_ip": "10.0.0.84",
  "dest_ip": "10.0.0.44",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos valid baseline test"
}' "200"

# Send corrupted payloads
send_payload "Extra field" "$EXTRA_FIELD" "422"
send_payload "Missing required" "$MISSING_FIELD" "422"
send_payload "Wrong type" "$WRONG_TYPE" "422"

# Send valid between corruptions
send_payload "Valid interleave 1" '{
  "alert_id": "CHAOS-VALID-2",
  "rule_id": 800300,
  "rule_description": "Interleave test 1",
  "alert_level": 1,
  "source_ip": "10.0.0.85",
  "dest_ip": "10.0.0.45",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos interleave test 1"
}' "200"

send_payload "Null fields" "$NULL_FIELDS" "422"
send_payload "Control characters" "$CONTROL_CHARS" "422"

send_payload "Valid interleave 2" '{
  "alert_id": "CHAOS-VALID-3",
  "rule_id": 800300,
  "rule_description": "Interleave test 2",
  "alert_level": 1,
  "source_ip": "10.0.0.86",
  "dest_ip": "10.0.0.46",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos interleave test 2"
}' "200"

send_payload "Oversized" "$OVERSIZED_FIELD" "422"

# Final valid
send_payload "Valid final" '{
  "alert_id": "CHAOS-VALID-4",
  "rule_id": 800300,
  "rule_description": "Final valid test",
  "alert_level": 1,
  "source_ip": "10.0.0.87",
  "dest_ip": "10.0.0.47",
  "agent_name": "chaos-corrupt",
  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
  "raw_log": "Chaos final valid test"
}' "200"

# 3. Validate state not corrupted
echo "--- Checking service health after corruption ---"
HEALTH=$(curl -sf http://localhost:8000/health)
echo "Health: $HEALTH"

echo "=== Results ==="
echo "Check that all valid requests succeeded and all malformed were rejected."
echo "If valid responses all returned 200 and malformed all returned 422: PASSED"
echo "=== Experiment Complete ==="
```

## Expected Results

| Observation | Expected | Actual |
|------------|----------|--------|
| Extra field payload | 422 | |
| Missing required field | 422 | |
| Wrong type payload | 422 | |
| Null fields payload | 422 | |
| Control characters | 422 (or sanitized) | |
| Oversized string | 422 (or truncated) | |
| Valid interleaved requests | 200 | |
| Service health after experiment | healthy | |
| Audit log entries | validation_failure recorded | |
