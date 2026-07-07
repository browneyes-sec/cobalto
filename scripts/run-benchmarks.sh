#!/bin/bash
# =============================================================================
# Cobalto SOC/MDR — Run Benchmarks (Developer Convenience)
# =============================================================================
# Thin wrapper around tests/benchmark/run.sh.
# Sets sensible defaults for local development.
#
# Usage:
#   ./scripts/run-benchmarks.sh                  # All benchmarks
#   ./scripts/run-benchmarks.sh --test auth_burst # Single test
#   ./scripts/run-benchmarks.sh --baseline        # Update baseline
#   ./scripts/run-benchmarks.sh --help            # Full help
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default: talk to local langgraph-agent
export COBALTO_BENCHMARK_URL="${COBALTO_BENCHMARK_URL:-http://localhost:8000}"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  Cobalto Performance Benchmarks                             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Target: $COBALTO_BENCHMARK_URL"
echo ""

# Verify target is reachable
if ! curl -sf "$COBALTO_BENCHMARK_URL/health" > /dev/null 2>&1; then
  echo "⚠ WARNING: $COBALTO_BENCHMARK_URL is not reachable."
  echo "  Start the service first:"
  echo "    cd services/langgraph-agent && python main.py"
  echo ""
  echo "  Or set COBALTO_BENCHMARK_URL to a running instance."
  echo ""
  read -rp "Continue anyway? (y/N) " yn
  if [[ ! "$yn" =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

exec "$PROJECT_ROOT/tests/benchmark/run.sh" "$@"
