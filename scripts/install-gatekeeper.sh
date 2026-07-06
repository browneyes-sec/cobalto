#!/bin/bash
# =============================================================================
# Install OPA Gatekeeper + Cobalto Constraint Templates
# =============================================================================
# Installs Gatekeeper admission controller via Helm, then applies the
# cobalto-specific constraint templates and constraints.
#
# Usage:
#   ./scripts/install-gatekeeper.sh                    # Install + apply
#   ./scripts/install-gatekeeper.sh --dry-run           # Dry run
#   ./scripts/install-gatekeeper.sh --uninstall        # Remove
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GATEKEEPER_NAMESPACE="gatekeeper-system"
CONSTRAINTS_DIR="$PROJECT_ROOT/kubernetes/security/gatekeeper"
ACTION="${1:-install}"

case "$ACTION" in
    --install|install|"")
        echo "=== Installing OPA Gatekeeper ==="

        # Add helm repo
        helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts 2>/dev/null || true
        helm repo update

        # Install Gatekeeper
        helm upgrade --install gatekeeper gatekeeper/gatekeeper \
            --namespace "$GATEKEEPER_NAMESPACE" \
            --create-namespace \
            --set audit.interval=60 \
            --set audit.constraintViolationsLimit=100 \
            --set audit.chunkSize=500 \
            --set replicas=1 \
            --set resources.requests.cpu=100m \
            --set resources.requests.memory=256Mi \
            --set resources.limits.cpu=500m \
            --set resources.limits.memory=512Mi

        echo "Waiting for Gatekeeper pods to be ready..."
        kubectl wait --for=condition=Available deployment/gatekeeper-webhook \
            --namespace "$GATEKEEPER_NAMESPACE" \
            --timeout=120s
        kubectl wait --for=condition=Available deployment/gatekeeper-audit \
            --namespace "$GATEKEEPER_NAMESPACE" \
            --timeout=120s

        echo ""
        echo "=== Applying Cobalto Constraint Templates ==="
        for template in "$CONSTRAINTS_DIR"/template-*.yaml; do
            echo "  Applying: $(basename "$template")"
            kubectl apply -f "$template"
        done

        echo ""
        echo "=== Applying Cobalto Constraints ==="
        echo "  Waiting for CRDs to be ready..."
        sleep 5
        for constraint in "$CONSTRAINTS_DIR"/constraint-*.yaml; do
            echo "  Applying: $(basename "$constraint")"
            kubectl apply -f "$constraint"
        done

        echo ""
        echo "=== Gatekeeper status ==="
        kubectl get constrainttemplates
        kubectl get constraints

        echo ""
        echo "Gatekeeper installed successfully!"
        ;;

    --dry-run)
        echo "=== Gatekeeper Dry Run ==="
        echo "Would install Gatekeeper via Helm:"
        echo "  helm upgrade --install gatekeeper gatekeeper/gatekeeper \\"
        echo "    --namespace $GATEKEEPER_NAMESPACE --create-namespace"
        echo ""
        echo "Would apply constraint templates:"
        for f in "$CONSTRAINTS_DIR"/template-*.yaml; do
            echo "  kubectl apply -f $f"
        done
        echo ""
        echo "Would apply constraints:"
        for f in "$CONSTRAINTS_DIR"/constraint-*.yaml; do
            echo "  kubectl apply -f $f"
        done
        ;;

    --uninstall|uninstall)
        echo "=== Uninstalling Gatekeeper ==="
        echo "Removing Cobalto constraints..."
        for constraint in "$CONSTRAINTS_DIR"/constraint-*.yaml; do
            kubectl delete -f "$constraint" 2>/dev/null || true
        done
        for template in "$CONSTRAINTS_DIR"/template-*.yaml; do
            kubectl delete -f "$template" 2>/dev/null || true
        done
        echo "Removing Gatekeeper Helm release..."
        helm uninstall gatekeeper --namespace "$GATEKEEPER_NAMESPACE" 2>/dev/null || true
        kubectl delete namespace "$GATEKEEPER_NAMESPACE" 2>/dev/null || true
        echo "Gatekeeper uninstalled."
        ;;

    *)
        echo "Usage: $0 [--install|--uninstall|--dry-run]"
        exit 1
        ;;
esac
