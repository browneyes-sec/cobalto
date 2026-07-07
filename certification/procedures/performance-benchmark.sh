#!/bin/bash
# =============================================================================
# Performance Certification Test
# =============================================================================
# Runs k6 benchmarks and compares against baselines:
#   1. Alert ingestion throughput (alert_ingestion.js)
#   2. Agent latency per severity (agent_latency.js)
#   3. Auth burst (auth_burst.js)
#   4. Health endpoint responsiveness (health_check.js)
#
# Usage:
#   ./certification/procedures/performance-benchmark.sh [--ci] [--baseline]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BENCHMARK_DIR="$PROJECT_ROOT/tests/benchmark"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Certification: Performance Benchmarks                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# ── Validate prerequisites ────────────────────────────────────────────────
if ! command -v k6 &>/dev/null && ! command -v docker &>/dev/null; then
  echo "ERROR: k6 or Docker required for performance benchmarks."
  echo "Install: https://k6.io/docs/getting-started/installation/"
  exit 1
fi

# ── Run benchmarks ─────────────────────────────────────────────────────────
echo "Target: ${COBALTO_BENCHMARK_URL:-http://localhost:8000}"
echo ""

BENCHMARK_ARGS=""
if [ "${1:-}" = "--ci" ]; then
  BENCHMARK_ARGS="--ci"
fi
if [ "${1:-}" = "--baseline" ]; then
  BENCHMARK_ARGS="--baseline"
fi

"$BENCHMARK_DIR/run.sh" $BENCHMARK_ARGS
BENCH_EXIT=$?

# ── Check results ──────────────────────────────────────────────────────────
echo ""
if [ "$BENCH_EXIT" -eq 0 ]; then
  echo "✅ Performance benchmarks: ALL WITHIN THRESHOLDS"
  exit 0
else
  echo "❌ Performance benchmarks: REGRESSIONS DETECTED"
  echo "   Check the benchmark report for details."
  echo "   To update baselines: make bench-baseline"
  exit 1
fi
