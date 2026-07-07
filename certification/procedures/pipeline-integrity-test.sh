#!/usr/bin/env bash
# =============================================================================
# Pipeline Integrity Test Procedure
# Validates end-to-end alert processing: ingestion → triage → analysis → report.
# Controls: PI-01 through PI-08, OB-07
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
EVIDENCE_DIR="$PROJECT_ROOT/certification/evidence/pipeline"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RUNNER="${RUNNER:-$(whoami)}"
HOSTNAME=$(hostname)
ENVIRONMENT="${ENVIRONMENT:-dev}"
API_BASE="${API_BASE:-http://localhost:8001}"

mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo " Cobalto Pipeline Integrity Test"
echo " Timestamp: $TIMESTAMP"
echo " API: $API_BASE"
echo "============================================"

# ── Helper: generate evidence ──
generate_evidence() {
    local control_id="$1"
    local status="$2"
    local metric_name="$3"
    local observed="$4"
    local threshold="$5"
    local passed="$6"
    local details="$7"
    local artifact_id
    artifact_id=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
    local filepath="$EVIDENCE_DIR/${control_id}_${TIMESTAMP}.json"
    local body
    body=$(cat <<EOF
{
  "artifact_id": "$artifact_id",
  "control_id": "$control_id",
  "domain": "pipeline-integrity",
  "procedure": "pipeline-integrity-test.sh",
  "timestamp": "$TIMESTAMP",
  "status": "$status",
  "result": {
    "metric_name": "$metric_name",
    "observed_value": $observed,
    "threshold": "$threshold",
    "passed": $passed,
    "details": "$details"
  },
  "chain_of_custody": {
    "runner": "$RUNNER",
    "hostname": "$HOSTNAME",
    "environment": "$ENVIRONMENT",
    "collection_method": "api_call"
  }
}
EOF
)
    local signature
    signature=$(echo -n "$body" | openssl dgst -sha256 -hmac "cert-runner" | cut -d' ' -f2)
    echo "$body" | python3 -c "
import json, sys
d = json.load(sys.stdin)
d['chain_of_custody']['signature'] = '$signature'
with open('$filepath', 'w') as f:
    json.dump(d, f, indent=2)
"
    echo "  ✓ Evidence saved: $filepath"
}

# ── PI-08 / OB-07: Health endpoint ──
echo ""
echo "--- PI-08 / OB-07: Health endpoint ---"
HEALTH=$(curl -sf "$API_BASE/health" 2>&1 || true)
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/health" 2>&1)
if [ "$HEALTH_CODE" = "200" ]; then
    echo "  ✓ Health endpoint: HTTP 200"
    generate_evidence "PI-08" "pass" "health_endpoint" "200" "200" true "Health endpoint returns 200"
    generate_evidence "OB-07" "pass" "health_endpoint" "200" "200" true "Service health endpoint responding"
else
    echo "  ✗ Health endpoint: HTTP $HEALTH_CODE"
    generate_evidence "PI-08" "fail" "health_endpoint" "$HEALTH_CODE" "200" false "Health endpoint not returning 200"
    generate_evidence "OB-07" "fail" "health_endpoint" "$HEALTH_CODE" "200" false "Service health endpoint not responding"
fi

# ── Also check /ready ──
READY_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/ready" 2>&1)
if [ "$READY_CODE" = "200" ]; then
    echo "  ✓ Readiness endpoint: HTTP 200"
else
    echo "  ✗ Readiness endpoint: HTTP $READY_CODE"
fi

# ── PI-01: Accept valid alert ──
echo ""
echo "--- PI-01: Valid alert ingestion ---"
ALERT_ID="pipeline-test-$(date +%s)"
RESPONSE=$(curl -sf -X POST "$API_BASE/agent/analyze" \
    -H "Content-Type: application/json" \
    -d "{
        \"alert_id\": \"$ALERT_ID\",
        \"rule_id\": 100001,
        \"rule_description\": \"Pipeline integrity test\",
        \"alert_level\": 8,
        \"source_ip\": \"10.0.0.99\",
        \"dest_ip\": \"192.168.1.200\",
        \"agent_name\": \"pipeline-test\",
        \"timestamp\": \"$TIMESTAMP\",
        \"raw_log\": \"Pipeline integrity test alert\"
    }" 2>&1 || echo '{"incident_id":"ERROR"}')

INCIDENT_ID=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('incident_id','NONE'))" 2>/dev/null || echo "PARSE_ERROR")

if [ -n "$INCIDENT_ID" ] && [ "$INCIDENT_ID" != "ERROR" ] && [ "$INCIDENT_ID" != "NONE" ] && [ "$INCIDENT_ID" != "PARSE_ERROR" ]; then
    echo "  ✓ Alert accepted: incident_id=$INCIDENT_ID"
    generate_evidence "PI-01" "pass" "alert_ingestion" "1" "1" true "Valid alert produced incident $INCIDENT_ID"
else
    echo "  ✗ Alert rejected or error. Response: $RESPONSE"
    generate_evidence "PI-01" "fail" "alert_ingestion" "0" "1" false "Valid alert was rejected: $(echo "$RESPONSE" | head -c 200)"
    INCIDENT_ID=""
fi

# ── PI-02: Reject malformed alert ──
echo ""
echo "--- PI-02: Malformed alert rejection ---"
MALFORMED_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/agent/analyze" \
    -H "Content-Type: application/json" \
    -d '{"bad_field": "no-rule-id"}' 2>&1)
if [ "$MALFORMED_CODE" = "422" ]; then
    echo "  ✓ Malformed alert correctly rejected: HTTP 422"
    generate_evidence "PI-02" "pass" "malformed_rejection" "422" "422" true "Malformed alert returns HTTP 422"
else
    echo "  ✗ Malformed alert returned HTTP $MALFORMED_CODE (expected 422)"
    generate_evidence "PI-02" "fail" "malformed_rejection" "$MALFORMED_CODE" "422" false "Malformed alert not rejected"
fi

# ── PI-03: Severity classification ──
echo ""
echo "--- PI-03: Severity classification ---"
if [ -n "${INCIDENT_ID:-}" ]; then
    SEVERITY=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('severity',''))" 2>/dev/null)
    if [ -n "$SEVERITY" ] && [ "$SEVERITY" != "NONE" ]; then
        echo "  ✓ Severity classified: $SEVERITY"
        generate_evidence "PI-03" "pass" "severity_classification" "\"$SEVERITY\"" "non-empty" true "Triage produced severity=$SEVERITY"
    else
        echo "  ✗ Severity not classified"
        generate_evidence "PI-03" "fail" "severity_classification" "\"\"" "non-empty" false "Triage did not classify severity"
    fi
else
    echo "  ⏭ Skipped (no incident from PI-01)"
    generate_evidence "PI-03" "skipped" "severity_classification" "null" "non-empty" false "Dependency on PI-01"
fi

# ── PI-04: Incident report produced ──
echo ""
echo "--- PI-04: Incident report ---"
if [ -n "${INCIDENT_ID:-}" ]; then
    REPORT=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('final_report',''))" 2>/dev/null)
    REPORT_LEN=${#REPORT}
    if [ "$REPORT_LEN" -gt 50 ]; then
        echo "  ✓ Incident report produced (${REPORT_LEN} chars)"
        generate_evidence "PI-04" "pass" "final_report_length" "$REPORT_LEN" "50" true "Incident report has content"
    else
        echo "  ✗ Incident report too short (${REPORT_LEN} chars)"
        generate_evidence "PI-04" "fail" "final_report_length" "$REPORT_LEN" "50" false "Incident report insufficient"
    fi
else
    echo "  ⏭ Skipped (no incident from PI-01)"
    generate_evidence "PI-04" "skipped" "final_report_length" "null" "50" false "Dependency on PI-01"
fi

# ── PI-05: Prometheus metrics increment ──
echo ""
echo "--- PI-05: Prometheus metrics increment ---"
sleep 2
ALERTS_METRIC=$(curl -sf "http://localhost:9090/api/v1/query?query=cobalto_alerts_received_total" 2>&1 | \
    python3 -c "import json,sys; d=json.load(sys.stdin); r=d['data']['result']; print(int(r[0]['value'][1]) if r else 0)" 2>/dev/null || echo "0")
if [ "$ALERTS_METRIC" -ge 1 ]; then
    echo "  ✓ Prometheus alert counter: $ALERTS_METRIC"
    generate_evidence "PI-05" "pass" "prometheus_alert_counter" "$ALERTS_METRIC" ">= 1" true "Prometheus recording alert metrics"
else
    echo "  ✗ Prometheus alert counter at 0"
    generate_evidence "PI-05" "fail" "prometheus_alert_counter" "0" ">= 1" false "Prometheus not recording alerts"
fi

# ── PI-06: Audit log captures alert ──
echo ""
echo "--- PI-06: Audit log captures alert ---"
AUDIT_LOG=$(docker logs cobalto-langgraph-agent --tail 100 2>&1 || echo "")
if echo "$AUDIT_LOG" | grep -q "alert_received"; then
    echo "  ✓ Audit log contains alert_received entry"
    generate_evidence "PI-06" "pass" "audit_log_alert_received" "1" "1" true "Audit log captures alert reception"
else
    echo "  ✗ Audit log missing alert_received entry"
    generate_evidence "PI-06" "fail" "audit_log_alert_received" "0" "1" false "Audit log does not contain alert_received"
fi

# ── PI-07: Webhook endpoint ──
echo ""
echo "--- PI-07: Webhook endpoint ---"
WEBHOOK_RESP=$(curl -s -X POST "$API_BASE/webhook/wazuh" \
    -H "Content-Type: application/json" \
    -d "{
        \"alert_id\": \"wh-pipe-$(date +%s)\",
        \"alert\": {
            \"rule_id\": \"100001\",
            \"rule_level\": 10,
            \"rule_description\": \"Webhook pipeline test\",
            \"agent_id\": \"001\",
            \"agent_name\": \"webhook-test\",
            \"srcip\": \"10.0.0.50\",
            \"dstip\": \"192.168.1.100\",
            \"timestamp\": \"$TIMESTAMP\",
            \"full_log\": \"Webhook pipeline integrity test\"
        },
        \"source\": \"wazuh\"
    }" 2>&1 || echo '{"incident_id":"ERROR"}')
WH_INCIDENT=$(echo "$WEBHOOK_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('incident_id','NONE'))" 2>/dev/null || echo "PARSE_ERROR")
if [ -n "$WH_INCIDENT" ] && [ "$WH_INCIDENT" != "ERROR" ] && [ "$WH_INCIDENT" != "NONE" ] && [ "$WH_INCIDENT" != "PARSE_ERROR" ]; then
    echo "  ✓ Webhook endpoint: incident_id=$WH_INCIDENT"
    generate_evidence "PI-07" "pass" "webhook_endpoint" "\"$WH_INCIDENT\"" "non-empty" true "Webhook produces incident reports"
else
    echo "  ✗ Webhook endpoint failed. Response: $(echo "$WEBHOOK_RESP" | head -c 200)"
    generate_evidence "PI-07" "fail" "webhook_endpoint" "\"$WH_INCIDENT\"" "non-empty" false "Webhook endpoint failed"
fi

echo ""
echo "============================================"
echo " Pipeline Integrity Test Complete"
echo "============================================"
