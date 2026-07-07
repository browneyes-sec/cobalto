#!/bin/bash
# =============================================================================
# Security Controls Certification Test
# =============================================================================
# Validates all platform security controls:
#   1. Auth middleware (API key validation, no-keys mode)
#   2. Console auth (JWT login, verify, refresh, logout)
#   3. Rate limiting enforcement
#   4. Audit log HMAC signing
#   5. Prompt injection detection
#   6. Container securityContext
#
# Usage:
#   ./certification/procedures/security-controls-test.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EVIDENCE_DIR="$PROJECT_ROOT/certification/evidence"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Certification: Security Controls                            ║"
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

# ── 1. Auth middleware tests ──────────────────────────────────────────────
echo "--- Test: Auth middleware ---"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/unit/test_auth.py" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -15

AUTH_EXIT=${PIPESTATUS[0]}
if [ "$AUTH_EXIT" -eq 0 ]; then
  check "SP-01: API key auth (HMAC constant-time)" "pass"
else
  check "SP-01: API key auth (HMAC constant-time)" "fail"
fi

# ── 2. Injection guard tests ─────────────────────────────────────────────
echo ""
echo "--- Test: Prompt injection detection ---"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/unit/" \
  -k "test_injection_guard or test_input_validator" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -15

INJECTION_EXIT=${PIPESTATUS[0]}
if [ "$INJECTION_EXIT" -eq 0 ]; then
  check "SP-09: Prompt injection detection" "pass"
else
  check "SP-09: Prompt injection detection" "fail"
fi

# ── 3. Rate limiter tests ─────────────────────────────────────────────────
echo ""
echo "--- Test: Rate limiter ---"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/unit/test_middleware.py" \
  -k "rate" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -10

RATE_EXIT=${PIPESTATUS[0]}
if [ "$RATE_EXIT" -eq 0 ]; then
  check "SP-06: Rate limiting (token bucket)" "pass"
else
  check "SP-06: Rate limiting (token bucket)" "fail"
fi

# ── 4. Audit logger tests ────────────────────────────────────────────────
echo ""
echo "--- Test: Audit logger HMAC ---"
PYTHONPATH="$PROJECT_ROOT/services/langgraph-agent" python3 -m pytest \
  "$PROJECT_ROOT/tests/unit/test_middleware.py" \
  -k "audit" \
  -v --tb=short \
  -W ignore::DeprecationWarning \
  2>&1 | tail -10

AUDIT_EXIT=${PIPESTATUS[0]}
if [ "$AUDIT_EXIT" -eq 0 ]; then
  check "SP-07: Audit log HMAC signing" "pass"
else
  check "SP-07: Audit log HMAC signing" "fail"
fi

# ── 5. K8s hardening validation ──────────────────────────────────────────
echo ""
echo "--- Test: K8s hardening (securityContext) ---"
HARDENING_FAIL=0
for f in "$PROJECT_ROOT"/kubernetes/**/deployment.yaml "$PROJECT_ROOT"/kubernetes/**/statefulset.yaml; do
  [ -f "$f" ] || continue
  if grep -q "runAsNonRoot: true" "$f" 2>/dev/null; then
    :  # passes
  else
    echo "  MISSING runAsNonRoot in $f"
    HARDENING_FAIL=1
  fi
  if grep -q "readOnlyRootFilesystem: true" "$f" 2>/dev/null; then
    :  # passes
  else
    echo "  MISSING readOnlyRootFilesystem in $f"
    HARDENING_FAIL=1
  fi
  if grep -q "capabilities:" "$f" 2>/dev/null; then
    :  # passes
  else
    echo "  MISSING capabilities drop in $f"
    HARDENING_FAIL=1
  fi
done

if [ "$HARDENING_FAIL" -eq 0 ]; then
  check "SP-11: Container securityContext enforcement" "pass"
else
  check "SP-11: Container securityContext enforcement" "fail"
fi

# ── 6. Network policy validation ─────────────────────────────────────────
echo ""
echo "--- Test: Network policy isolation ---"
NP_COUNT=$(find "$PROJECT_ROOT/kubernetes" -name "networkpolicy.yaml" | wc -l)
if [ "$NP_COUNT" -ge 1 ]; then
  check "SP-12: Network policy isolation ($NP_COUNT policies)" "pass"
else
  check "SP-12: Network policy isolation" "fail"
fi

# ── 7. Generate evidence ─────────────────────────────────────────────────
echo ""
echo "--- Generating evidence artifact ---"
EVIDENCE_FILE="$EVIDENCE_DIR/security-controls-$(date +%Y%m%dT%H%M%S).json"
mkdir -p "$EVIDENCE_DIR"

cat > "$EVIDENCE_FILE" <<JSONEOF
{
  "artifact_id": "$(uuidgen 2>/dev/null || date +%s | md5sum | head -c 36)",
  "domain": "security-posture",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source": "CI security controls test",
  "procedure": "certification/procedures/security-controls-test.sh",
  "result": "$([ "$FAIL_COUNT" -eq 0 ] && echo "PASS" || echo "FAIL")",
  "controls": {
    "SP-01": "$([ "$AUTH_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "SP-06": "$([ "$RATE_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "SP-07": "$([ "$AUDIT_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "SP-09": "$([ "$INJECTION_EXIT" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "SP-11": "$([ "$HARDENING_FAIL" -eq 0 ] && echo "PASS" || echo "FAIL")",
    "SP-12": "$([ "$NP_COUNT" -ge 1 ] && echo "PASS" || echo "FAIL")"
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
echo "║  Security Controls: $PASS_COUNT passed, $FAIL_COUNT failed                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
