#!/bin/bash
# =============================================================================
# Cobalto SOC/MDR — Benchmark Runner
# =============================================================================
# Orchestrates k6 benchmarks: runs each test, collects results, compares
# against baselines, and generates a summary report.
#
# Prerequisites:
#   - k6 >= 0.55 (or Docker: `alias k6='docker run --rm -i grafana/k6'`)
#   - The target service must be reachable at $COBALTO_BENCHMARK_URL
#
# Usage:
#   ./tests/benchmark/run.sh                          # Run all benchmarks
#   ./tests/benchmark/run.sh --test alert_ingestion   # Run single test
#   ./tests/benchmark/run.sh --baseline               # Update baseline with results
#   ./tests/benchmark/run.sh --ci                     # CI mode (JSON output, exit code)
#   ./tests/benchmark/run.sh --list                   # List available tests
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BASELINE_DIR="$SCRIPT_DIR/baselines"
REPORT_DIR="${COBALTO_BENCHMARK_REPORT_DIR:-$SCRIPT_DIR/reports}"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
SUMMARY_FILE="$REPORT_DIR/summary-$TIMESTAMP.json"

# k6 binary or Docker alias
if command -v k6 &>/dev/null; then
  K6="k6"
elif command -v docker &>/dev/null; then
  K6="docker run --rm -i -v $SCRIPT_DIR:/scripts -v $REPORT_DIR:/reports \
       --network host grafana/k6:latest run"
else
  echo "ERROR: Neither k6 nor Docker found. Install k6 or Docker."
  exit 1
fi

# ── Helpers ─────────────────────────────────────────────────────────────────

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --test <name>       Run a single benchmark test"
  echo "  --baseline          Update baseline with current results"
  echo "  --ci                CI mode: JSON summary, fail on regression"
  echo "  --list              List available benchmark tests"
  echo "  --help              Show this help"
  echo ""
  echo "Environment:"
  echo "  COBALTO_BENCHMARK_URL   Target URL (default: http://localhost:8000)"
  echo "  COBALTO_API_KEY         API key for auth (default: none)"
  echo "  COBALTO_BENCHMARK_REPORT_DIR  Report output directory"
}

list_tests() {
  echo "Available benchmarks:"
  for f in "$SCRIPT_DIR"/*.js; do
    name=$(basename "$f" .js)
    desc=$(head -5 "$f" | grep -oP '// \K.+')
    echo "  $name  — ${desc:-No description}"
  done
}

# ── Parse args ──────────────────────────────────────────────────────────────

SINGLE_TEST=""
UPDATE_BASELINE=false
CI_MODE=false

for arg in "$@"; do
  case $arg in
    --test) SINGLE_TEST="$2"; shift 2 ;;
    --baseline) UPDATE_BASELINE=true; shift ;;
    --ci) CI_MODE=true; shift ;;
    --list) list_tests; exit 0 ;;
    --help) usage; exit 0 ;;
  esac
done

mkdir -p "$REPORT_DIR"

# ── Tests to run ────────────────────────────────────────────────────────────

ALL_TESTS=(
  "health_check"
  "auth_burst"
  "alert_ingestion"
  "agent_latency"
)

if [ -n "$SINGLE_TEST" ]; then
  if [ -f "$SCRIPT_DIR/$SINGLE_TEST.js" ]; then
    ALL_TESTS=("$SINGLE_TEST")
  else
    echo "ERROR: Unknown test '$SINGLE_TEST'"
    list_tests
    exit 1
  fi
fi

# ── Run Benchmarks ──────────────────────────────────────────────────────────

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Cobalto Performance Benchmark Suite                         ║"
echo "║  Target: ${COBALTO_BENCHMARK_URL:-http://localhost:8000}                 "
echo "║  Started: $TIMESTAMP                                        "
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

ALL_RESULTS="{}"

for test_name in "${ALL_TESTS[@]}"; do
  echo ""
  echo "=== Running: $test_name ==="

  RESULT_FILE="$REPORT_DIR/$test_name-$TIMESTAMP.json"
  K6_OUT="--out json=$RESULT_FILE --summary-export=$RESULT_FILE.summary"

  # Run k6
  K6_CMD="$K6"
  if [[ "$K6" == "k6" ]]; then
    # Local k6 binary
    k6 run "$SCRIPT_DIR/$test_name.js" \
      --summary-export="$RESULT_FILE.summary" \
      --out "json=$RESULT_FILE" \
      2>&1 | tee "$REPORT_DIR/$test_name-$TIMESTAMP.log"
  else
    # Docker-based k6 — file paths are container-relative
    cp "$SCRIPT_DIR/$test_name.js" /tmp/k6-test.js
    $SHELL -c "$K6 /scripts/$test_name.js 2>&1" | tee "$REPORT_DIR/$test_name-$TIMESTAMP.log"
    rm -f /tmp/k6-test.js
  fi

  echo "  Results: $RESULT_FILE"
done

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  All benchmarks complete                                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# ── Baseline Comparison ────────────────────────────────────────────────────

if [ "$UPDATE_BASELINE" = false ]; then
  BASELINE_FILE="$BASELINE_DIR/v1.json"
  if [ -f "$BASELINE_FILE" ]; then
    echo "=== Comparing against baseline: $BASELINE_FILE ==="
    python3 "$SCRIPT_DIR/compare_baseline.py" \
      --baseline "$BASELINE_FILE" \
      --results-dir "$REPORT_DIR" \
      --timestamp "$TIMESTAMP" \
      --summary "$SUMMARY_FILE"
    
    COMPARE_EXIT=$?
    if [ $COMPARE_EXIT -ne 0 ]; then
      if [ "$CI_MODE" = true ]; then
        echo "❌ PERFORMANCE REGRESSION DETECTED"
        exit 1
      else
        echo "⚠ Performance regression detected (non-fatal in local mode)"
      fi
    else
      echo "✅ All metrics within baseline thresholds"
    fi
  else
    echo "No baseline file found at $BASELINE_FILE. Skipping comparison."
    echo "Run with --baseline to create the initial baseline."
  fi
else
  echo "=== Updating baseline with current results ==="
  # Copy the latest results as the new baseline summary
  python3 "$SCRIPT_DIR/compare_baseline.py" \
    --results-dir "$REPORT_DIR" \
    --timestamp "$TIMESTAMP" \
    --update-baseline "$BASELINE_DIR/v1.json" \
    --summary "$SUMMARY_FILE"
  echo "✅ Baseline updated"
fi

echo ""
echo "Summary: $SUMMARY_FILE"
exit 0
