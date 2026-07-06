#!/bin/bash
# =============================================================================
# Cobalto E2E — Deploy to Kind and Run Tests
# =============================================================================
# Spins up a kind cluster, builds Docker images, deploys all cobalto services,
# and runs the E2E test suite.
#
# Prerequisites:
#   - kind, kubectl, docker, helm
#   - Python 3.11+ with pytest, httpx
#
# Usage:
#   ./scripts/e2e-deploy.sh                  # Deploy + test
#   ./scripts/e2e-deploy.sh --skip-tests      # Deploy only
#   ./scripts/e2e-deploy.sh --skip-build      # Use existing images
#   ./scripts/e2e-deploy.sh --test-only       # Run tests on existing cluster
#   ./scripts/e2e-deploy.sh --cleanup         # Delete cluster
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER_NAME="cobalto-e2e"
KIND_CONFIG="$PROJECT_ROOT/tests/e2e/kind/cluster.yaml"
E2E_URL="${COBALTO_E2E_URL:-http://localhost:8000}"
E2E_USER="${COBALTO_E2E_USER:-testadmin}"
E2E_PASS="${COBALTO_E2E_PASS:-testpassword123}"
JWT_SECRET="${COBALTO_JWT_SECRET:-e2e-test-jwt-secret-do-not-use-in-prod}"

# ── Step 0: Parse args ───────────────────────────────────────────────

SKIP_TESTS=false
SKIP_BUILD=false
TEST_ONLY=false
CLEANUP=false

for arg in "$@"; do
    case $arg in
        --skip-tests) SKIP_TESTS=true ;;
        --skip-build) SKIP_BUILD=true ;;
        --test-only) TEST_ONLY=true ;;
        --cleanup) CLEANUP=true ;;
    esac
done

if [ "$CLEANUP" = true ]; then
    echo "=== Cleaning up kind cluster: $CLUSTER_NAME ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    echo "Done."
    exit 0
fi

# ── Step 1: Create kind cluster ─────────────────────────────────────

if [ "$TEST_ONLY" = false ]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  Cobalto E2E — Deploy to Kind                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""

    echo "=== Step 1: Creating kind cluster: $CLUSTER_NAME ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    kind create cluster --config "$KIND_CONFIG" --name "$CLUSTER_NAME"
    echo ""

    # ── Step 2: Build Docker images ──────────────────────────────────

    if [ "$SKIP_BUILD" = false ]; then
        echo "=== Step 2: Building Docker images ==="

        # Build auth service
        echo "  Building console-auth..."
        docker build -t cobalto/console-auth:latest \
            "$PROJECT_ROOT/services/console-auth/" 2>&1 | tail -1

        # Build langgraph agent
        echo "  Building langgraph-agent..."
        docker build -t cobalto/langgraph-agent:latest \
            "$PROJECT_ROOT/services/langgraph-agent/" 2>&1 | tail -1

        # Build console
        echo "  Building cobalt-console..."
        docker build -t cobalto/cobalt-console:latest \
            "$PROJECT_ROOT/services/cobalt-console/" 2>&1 | tail -1

        # Load images into kind
        echo "  Loading images into kind..."
        kind load docker-image cobalto/console-auth:latest \
            --name "$CLUSTER_NAME"
        kind load docker-image cobalto/langgraph-agent:latest \
            --name "$CLUSTER_NAME"
        kind load docker-image cobalto/cobalt-console:latest \
            --name "$CLUSTER_NAME"

        echo ""
    fi

    # ── Step 3: Create auth secrets ──────────────────────────────────

    echo "=== Step 3: Creating auth secrets ==="

    # Generate bcrypt hash for test user
    BCRYPT_HASH=$(python3 -c "
import bcrypt
hash = bcrypt.hashpw(b'$E2E_PASS', bcrypt.gensalt(rounds=4))
print(hash.decode())
" 2>/dev/null) || {
        echo "ERROR: Failed to generate bcrypt hash. Is bcrypt installed?"
        echo "  pip install bcrypt"
        exit 1
    }

    USERS_STRING="testadmin:${BCRYPT_HASH}:admin:Test Admin,analyst:${BCRYPT_HASH}:analyst:Jane Analyst"

    kubectl create secret generic console-auth-secrets \
        --namespace cobalto \
        --from-literal=jwt_secret="$JWT_SECRET" \
        --from-literal=users="$USERS_STRING" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo "  Auth secrets created"
    echo ""

    # ── Step 4: Deploy services ──────────────────────────────────────

    echo "=== Step 4: Deploying services ==="

    # Apply auth service
    echo "  Deploying console-auth..."
    kubectl apply -f "$PROJECT_ROOT/services/console-auth/kubernetes/"

    # Deploy langgraph agent
    echo "  Deploying langgraph-agent..."
    kubectl apply -f "$PROJECT_ROOT/services/langgraph-agent/kubernetes/" 2>/dev/null || {
        echo "  (langgraph-agent K8s manifests not found, using docker-compose)"
    }

    # Apply console
    echo "  Deploying cobalt-console..."
    kubectl apply -f "$PROJECT_ROOT/services/cobalt-console/kubernetes/cobalt-console/"

    echo ""

    # ── Step 5: Wait for deployments ─────────────────────────────────

    echo "=== Step 5: Waiting for deployments to be ready ==="
    echo "  (this may take a few minutes on first deploy)"

    for deployment in console-auth cobalt-console; do
        echo "  Waiting for $deployment..."
        kubectl wait --for=condition=Available deployment/"$deployment" \
            --namespace cobalto --timeout=300s 2>/dev/null || {
            echo "  WARNING: $deployment not ready within timeout"
        }
    done

    echo ""
    echo "=== Deployment complete ==="
    echo ""
fi

# ── Step 6: Run E2E tests ───────────────────────────────────────────

if [ "$SKIP_TESTS" = false ]; then
    echo "=== Step 6: Running E2E tests ==="
    echo ""

    # Set up test env
    export COBALTO_E2E_URL="$E2E_URL"
    export COBALTO_E2E_USER="$E2E_USER"
    export COBALTO_E2E_PASS="$E2E_PASS"

    cd "$PROJECT_ROOT"

    # Check required Python packages
    python3 -c "import pytest, httpx" 2>/dev/null || {
        echo "Installing test dependencies..."
        pip install pytest httpx 2>&1 | tail -1
    }

    # Run tests
    python3 -m pytest tests/e2e/ \
        -v \
        --tb=long \
        --junit-xml=reports/e2e-results.xml \
        -W ignore::DeprecationWarning \
        2>&1 | tee /tmp/cobalto-e2e-results.log

    EXIT_CODE=${PIPESTATUS[0]}

    echo ""
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║  ALL E2E TESTS PASSED                                       ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
    else
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║  SOME E2E TESTS FAILED (exit code: $EXIT_CODE)              ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
    fi

    exit "$EXIT_CODE"
fi

echo "=== Done ==="
