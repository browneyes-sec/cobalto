#!/bin/bash
# =============================================================================
# Pipeline Integrity Certification Test
# =============================================================================
# Validates that the alert processing pipeline preserves data integrity:
#   1. Input validation rejects malformed payloads
#   2. Schema lock prevents extra fields
#   3. HMAC receipts are generated for all tool calls
#   4. Pipeline completes on all known severity pathways
#   5. Error paths produce logged failures
#
# Usage:
#   ./certification/procedures/pipeline-integrity-test.sh
#
# Returns: 0 if all controls pass, 1 if any fail
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EVIDENCE_DIR="$PROJECT_ROOT/certification/evidence"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Certification: Pipeline Integrity                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

FAIL_COUNT=0
PASS_COUNT=0

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "pass" ]; then
    echo "  ✅ $desc"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "  ❌ $desc"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# ── 1. Run integration tests ──────────────────────────────────────────────
echo "--- Test: Integration tests (pipeline coverage) ---"
cd "$PROJECT_ROOT/services/langgraph-agent"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/integration/" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -20

INTEGRATION_EXIT=${PIPESTATUS[0]}
if [ "$INTEGRATION_EXIT" -eq 0 ]; then
  check "PI-06: Pipeline completes on known pathways" "pass"
else
  check "PI-06: Pipeline completes on known pathways" "fail"
fi

# ── 2. Run input validation tests ────────────────────────────────────────
echo ""
echo "--- Test: Input validation & schema lock ---"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/integration/test_api.py" \
  -k "test_analyze_missing_required_field or test_analyze_empty_body or test_analyze_invalid_alert_level or test_analyze_additional_properties_rejected" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -15

VALIDATION_EXIT=${PIPESTATUS[0]}
if [ "$VALIDATION_EXIT" -eq 0 ]; then
  check "PI-01: Input validation rejects malformed payloads" "pass"
  check "PI-02: Schema lock prevents extra fields" "pass"
else
  check "PI-01: Input validation rejects malformed payloads" "fail"
  check "PI-02: Schema lock prevents extra fields" "fail"
fi

# ── 3. Verify HMAC audit logging ─────────────────────────────────────────
echo ""
echo "--- Test: HMAC audit receipt generation ---"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/unit/test_middleware.py" \
  -k "test_audit_logger" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -15

AUDIT_EXIT=${PIPESTATUS[0]}
if [ "$AUDIT_EXIT" -eq 0 ]; then
  check "PI-04: HMAC receipt generated for every tool call" "pass"
else
  check "PI-04: HMAC receipt generated for every tool call" "fail"
fi

# ── 4. Verify error path handling ────────────────────────────────────────
echo ""
echo "--- Test: Error path handling ---"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/integration/test_api.py" \
  -k "failure or error" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -15

ERROR_EXIT=${PIPESTATUS[0]}
if [ "$ERROR_EXIT" -eq 0 ]; then
  check "PI-07: Error paths produce logged failures" "pass"
else
  check "PI-07: Error paths produce logged failures" "fail"
fi

# ── 5. Generate evidence ─────────────────────────────────────────────────
echo ""
echo "--- Generating evidence artifact ---"
EVIDENCE_FILE="$EVIDENCE_DIR/pipeline-integrity-$(date +%Y%m%dT%H%M%S).json"
mkdir -p "$EVIDENCE_DIR"

cat > "$EVIDENCE_FILE" <<JSONEOF
{
  "artifact_id": "$(uuidgen 2>/dev/null || date +%s | md5sum | head -c 36)",
  "domain": "pipeline-integrity",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source": "CI pipeline integrity test",
  "procedure": "certification/procedures/pipeline-integrity-test.sh",
  "result": "$([ "$FAIL_COUNT" -eq 0 ] && echo "PASS" || echo "FAIL")",
  "controls": {
    "PI-01": "$([ "$VALIDATION_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "PI-02": "$([ "$VALIDATION_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "PI-04": "$([ "$AUDIT_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "PI-06": "$([ "$INTEGRATION_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "PI-07": "$([ "$ERROR_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")"
  },
  "summary": {
    "total": $((PASS_COUNT + FAIL_COUNT)),
    "passed": $PASS_COUNT,
    "failed": $FAIL_COUNT
  }
}
JSONEOF

echo "Evidence written: $EVIDENCE_FILE"

# ── Result ─────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Pipeline Integrity: $PASS_COUNT passed, $FAIL_COUNT failed                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
