#!/usr/bin/env bash
# ==============================================================================
# Cobalto Vault Setup for External Secrets Operator
#
# Configures Vault with the secrets paths and auth roles needed by ESO.
# Run AFTER Vault is initialized and unsealed.
#
# Usage:
#   ./scripts/vault-setup.sh                          # Interactive
#   VAULT_ADDR=http://localhost:8200 ./scripts/vault-setup.sh  # Custom address
#
# Prerequisites:
#   - Vault pod is running and unsealed
#   - kubectl is configured with cluster access
#   - VAULT_TOKEN is available (from vault init output)
# ==============================================================================

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
NAMESPACE="${NAMESPACE:-vault}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[VAULT]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Verify access ──────────────────────────────────────────────────

check_vault() {
  if ! curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
    error "Cannot reach Vault at $VAULT_ADDR"
    exit 1
  fi
  log "Vault is reachable at $VAULT_ADDR"
}

check_token() {
  if [ -z "$VAULT_TOKEN" ]; then
    # Try to get from k8s secret
    log "No VAULT_TOKEN set. Attempting to read from K8s secret 'vault-unseal-keys'..."
    VAULT_TOKEN=$(kubectl get secret vault-unseal-keys -n "$NAMESPACE" -o jsonpath='{.data.root_token}' 2>/dev/null | base64 -d || echo "")
    
    if [ -z "$VAULT_TOKEN" ]; then
      warn "Could not retrieve Vault token from K8s secret."
      warn "Please set VAULT_TOKEN environment variable."
      echo ""
      read -rsp "Enter Vault root token: " VAULT_TOKEN
      echo ""
    fi
  fi
  export VAULT_TOKEN
  log "Vault token configured"
}

# ── Configure Vault for ESO ────────────────────────────────────────

enable_secrets_engine() {
  log "Enabling KV v2 secrets engine at 'secret/'..."
  curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d '{"type": "kv-v2"}' \
    "$VAULT_ADDR/v1/sys/mounts/secret" || {
    warn "Mount may already exist. Continuing..."
  }
  log "KV v2 secrets engine enabled"
}

enable_kubernetes_auth() {
  log "Enabling Kubernetes auth method..."
  curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d '{"type": "kubernetes"}' \
    "$VAULT_ADDR/v1/sys/auth/kubernetes" || {
    warn "K8s auth may already be enabled. Continuing..."
  }
}

configure_kubernetes_auth() {
  log "Configuring Kubernetes auth..."

  # Get service account info from the running pod
  local kube_host
  kube_host=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

  local sa_token
  sa_token=$(kubectl get secret -n "$NAMESPACE" -o name | grep vault | head -1 | xargs kubectl get -n "$NAMESPACE" -o jsonpath='{.data.token}' 2>/dev/null | base64 -d || echo "")

  if [ -z "$sa_token" ]; then
    # Try reading from the pod's service account
    sa_token=$(kubectl exec -n "$NAMESPACE" deploy/vault -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo "")
  fi

  local ca_cert
  ca_cert=$(kubectl get secret -n "$NAMESPACE" -o name | grep vault | head -1 | xargs kubectl get -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d || echo "")

  if [ -n "$sa_token" ] && [ -n "$kube_host" ]; then
    curl -s -X POST \
      -H "X-Vault-Token: $VAULT_TOKEN" \
      -d "{
        \"kubernetes_host\": \"$kube_host\",
        \"token_reviewer_jwt\": \"$sa_token\",
        \"kubernetes_ca_cert\": $(echo "$ca_cert" | jq -Rs '.')
      }" \
      "$VAULT_ADDR/v1/auth/kubernetes/config"
    log "Kubernetes auth configured"
  else
    warn "Could not auto-configure K8s auth. Please configure manually:"
    echo "  vault write auth/kubernetes/config \\"
    echo "    kubernetes_host=\"$kube_host\" \\"
    echo "    token_reviewer_jwt=\"@/var/run/secrets/kubernetes.io/serviceaccount/token\" \\"
    echo "    kubernetes_ca_cert=\"@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\""
  fi
}

create_policies() {
  log "Creating application policy 'cobalto-app'..."
  curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d '{
      "policy": "path \"secret/data/cobalto/*\" { capabilities = [\"read\"] }\npath \"secret/metadata/cobalto/*\" { capabilities = [\"list\"] }"
    }' \
    "$VAULT_ADDR/v1/sys/policies/acl/cobalto-app" || true
  log "Policy 'cobalto-app' created"
}

create_auth_role() {
  log "Creating Kubernetes auth role 'cobalto-app-role'..."
  curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d '{
      "bound_service_account_names": ["langgraph-sa", "console-sa", "n8n-sa"],
      "bound_service_account_namespaces": ["langgraph", "cobalt-console", "n8n"],
      "policies": ["cobalto-app"],
      "ttl": "1h"
    }' \
    "$VAULT_ADDR/v1/auth/kubernetes/role/cobalto-app-role"
  log "Auth role 'cobalto-app-role' created"
}

seed_secrets() {
  log "Seeding initial secrets..."

  # Generate random secrets if none exist
  local OPENAI_KEY="${COBALTO_OPENAI_API_KEY:-sk-placeholder}"
  local HMAC_SECRET="${COBALTO_HMAC_SECRET:-$(openssl rand -hex 32)}"
  local SESSION_SECRET="${COBALTO_SESSION_SECRET:-$(openssl rand -hex 32)}"

  # LangGraph secrets
  curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d "{\"data\": {\"api_key\": \"$OPENAI_KEY\"}}" \
    "$VAULT_ADDR/v1/secret/data/cobalto/langgraph/openai" || true

  curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d "{\"data\": {\"secret\": \"$HMAC_SECRET\"}}" \
    "$VAULT_ADDR/v1/secret/data/cobalto/langgraph/hmac" || true

  # Console secrets
  curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d "{\"data\": {\"secret\": \"$SESSION_SECRET\"}}" \
    "$VAULT_ADDR/v1/secret/data/cobalto/console/session" || true

  log "Initial secrets seeded"
  warn "Replace placeholder values with real secrets in production!"
  warn "  COBALTO_OPENAI_API_KEY: $OPENAI_KEY"
  warn "  HMAC_SECRET: $HMAC_SECRET (last 8 chars: ${HMAC_SECRET: -8})"
}

# ── Main ────────────────────────────────────────────────────────────

main() {
  echo ""
  echo "╔═══════════════════════════════════════════════╗"
  echo "║     Cobalto Vault ESO Setup                  ║"
  echo "╚═══════════════════════════════════════════════╝"
  echo ""

  check_vault
  check_token

  echo ""
  echo "1/6 Enabling KV v2 secrets engine..."
  enable_secrets_engine

  echo ""
  echo "2/6 Enabling Kubernetes auth..."
  enable_kubernetes_auth

  echo ""
  echo "3/6 Configuring Kubernetes auth..."
  configure_kubernetes_auth

  echo ""
  echo "4/6 Creating policies..."
  create_policies

  echo ""
  echo "5/6 Creating auth role..."
  create_auth_role

  echo ""
  echo "6/6 Seeding secrets..."
  seed_secrets

  echo ""
  log "=== Vault ESO Setup Complete ==="
  echo ""
  echo "Next steps:"
  echo "  1. Verify: kubectl get secretstores -A"
  echo "  2. Verify: kubectl get externalsecrets -A"
  echo "  3. Check: kubectl get secret langgraph-secrets -n langgraph"
  echo "  4. Deploy the platform: kubectl apply -k kubernetes/overlays/dev/"
  echo ""
}

main "$@"
