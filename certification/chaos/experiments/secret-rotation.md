# Chaos Experiment: Secret Rotation — Vault PKI Expiry

> **Domain:** Security Posture / Data Governance  
> **Blast Radius:** Namespace (default)  
> **CI-Safe:** ✅ (non-production only)  
> **Tool:** Vault CLI + `kubectl`

## Hypothesis

**Given** Vault PKI issues certificates with 24-hour TTL and Istio auto-rotates,  
**When** PKI certificates are forced to expire during active alert processing,  
**Then** existing connections continue (TLS session reuse),  
**And** new connections are established with renewed certificates,  
**And** no authentication failures occur during rotation.

## Steady State

| Metric | Pre-Experiment | During | Post-Experiment |
|--------|---------------|--------|-----------------|
| TLS handshake success | 100% | 100% | 100% |
| Alert processing success | 100% | 100% | 100% |
| Certificate expiry (min remaining) | > 12h | < 5min | > 12h |
| Audit log entries | normal | rotation events | normal |

## Experiment Design

```yaml
kind: ChaosExperiment
metadata:
  name: vault-pki-rotation
  domain: security-posture
spec:
  duration: 120s
  interval: 30s
  target:
    app: langgraph-agent
    namespace: cobalto
  experiment:
    - action: vault-pki-rotate
      mount: pki
      issue_new: true
      revoke_old: true
      grace_period: 30s
  steady_state:
    - metric: "tls_handshake_success_rate"
      threshold: "= 100%"
    - metric: "alert_success_rate"
      threshold: "= 100%"
    - metric: "certificate_expiry"
      threshold: "renewed before expiry"
  rollback:
    method: "Vault PKI automatic renewal with grace period"
    max_duration: 60s
```

## Procedure

```bash
#!/bin/bash
set -euo pipefail

echo "=== Secret Rotation Experiment: Vault PKI ==="
echo "This experiment requires Vault CLI and valid Vault token."

# Guard: ensure not production
if [ "${COBALTO_ENV:-}" = "production" ]; then
  echo "ERROR: This experiment must NOT run in production"
  exit 1
fi

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

if [ -z "$VAULT_TOKEN" ]; then
  echo "WARNING: No Vault token set. Running in verification-only mode."
  echo "To run full experiment: export VAULT_TOKEN=..."
fi

# 1. Record current certificate state
echo "--- Recording current certificate state ---"
if command -v vault &>/dev/null && [ -n "$VAULT_TOKEN" ]; then
  CURRENT_CERTS=$(vault list pki/certs 2>/dev/null | head -5 || echo "No certs listed")
  echo "Current certificates: $CURRENT_CERTS"

  # Get expiration of first cert
  FIRST_CERT=$(vault list pki/certs 2>/dev/null | tail -1)
  if [ -n "$FIRST_CERT" ] && [ "$FIRST_CERT" != "Keys" ]; then
    CERT_INFO=$(vault read -format=json "pki/cert/$FIRST_CERT" 2>/dev/null || echo "{}")
    echo "Certificate info: $(echo "$CERT_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('expiration','unknown'))" 2>/dev/null)"
  fi
fi

# 2. Force certificate rotation (if Vault available)
if command -v vault &>/dev/null && [ -n "$VAULT_TOKEN" ]; then
  echo "--- Forcing PKI certificate rotation ---"
  VAULT_TOKEN="$VAULT_TOKEN" vault write -f pki/rotate 2>/dev/null || {
    echo "WARNING: PKI rotation command failed (may be read-only)"
  }

  # Issue new certificate for the test service
  echo "Issuing new certificate for langgraph-agent..."
  VAULT_TOKEN="$VAULT_TOKEN" vault write pki/issue/langgraph-agent \
    common_name="langgraph-agent.cobalto.svc.cluster.local" \
    ttl="1h" \
    2>/dev/null || {
    echo "WARNING: Could not issue new certificate"
  }
else
  echo "Vault not available. Skipping rotation (verification-only mode)."
fi

# 3. Verify TLS connectivity during rotation
echo "--- Verifying TLS during rotation ---"
for i in $(seq 1 5); do
  # Attempt TLS handshake to each service
  for service in langgraph-agent qdrant elasticsearch; do
    # Use openssl to verify TLS
    if command -v openssl &>/dev/null; then
      CERT_EXPIRY=$(echo | openssl s_client -connect "$service:443" \
        -servername "$service" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null || echo "unknown")
      echo "  $service: $CERT_EXPIRY"
    fi
  done
  sleep 2
done

# 4. Send test alerts to verify processing
echo "--- Verifying alert processing during rotation ---"
for i in $(seq 1 3); do
  curl -sf -X POST http://localhost:8000/agent/analyze \
    -H 'Content-Type: application/json' \
    -d "{\"alert_id\":\"CHAOS-SR-$i\",\"rule_id\":800300,\"rule_description\":\"Secret rotation test\",\"alert_level\":1,\"source_ip\":\"10.0.0.70\",\"dest_ip\":\"10.0.0.30\",\"agent_name\":\"chaos-sr\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"raw_log\":\"Secret rotation chaos test\"}" \
    -w "  Status: %{http_code}\n"
done

# 5. Validate
echo "=== Results ==="
echo "If no TLS errors occurred and all alerts returned 200: PASSED"
echo "Otherwise: FAILED — check certificate renewal mechanism"
echo "=== Experiment Complete ==="
```

## Expected Results

| Observation | Expected | Actual |
|------------|----------|--------|
| TLS handshakes during rotation | 100% success (session reuse) | |
| Alert processing during rotation | 100% success | |
| New connections after rotation | 100% success (renewed certs) | |
| Vault audit log entries | Rotation events recorded | |
| Service disruption | 0% | |
