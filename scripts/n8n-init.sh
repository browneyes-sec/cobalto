#!/usr/bin/env bash
set -euo pipefail

N8N_BASE_URL="${N8N_BASE_URL:-http://localhost:5678}"
N8N_API_URL="${N8N_API_URL:-http://localhost:5678/api/v1}"
WORKFLOW_DIR="${WORKFLOW_DIR:-/workflows/n8n}"
MAX_RETRIES=60
RETRY_INTERVAL=5

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"; }
die() { log "FATAL: $*"; exit 1; }

wait_for_n8n() {
  log "Waiting for n8n to be ready at ${N8N_BASE_URL}..."
  local attempt=0
  while (( attempt < MAX_RETRIES )); do
    if curl -sf "${N8N_BASE_URL}/healthz" >/dev/null 2>&1 || \
       curl -sf "${N8N_BASE_URL}/health" >/dev/null 2>&1; then
      log "n8n is ready."
      return 0
    fi
    (( attempt++ ))
    sleep "${RETRY_INTERVAL}"
  done
  die "n8n did not become ready after $((MAX_RETRIES * RETRY_INTERVAL))s"
}

import_workflow() {
  local file="$1"
  local name
  name=$(basename "$file" .json)
  log "Importing workflow: ${name}"

  local payload
  payload=$(cat "$file")

  local response
  response=$(curl -s -w "\n%{http_code}" -X POST "${N8N_API_URL}/workflows" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "$payload")

  local http_code
  http_code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')

  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    local workflow_id
    workflow_id=$(echo "$body" | jq -r '.id // empty')
    log "Imported workflow '${name}' with ID: ${workflow_id}"
    echo "$workflow_id"
    return 0
  else
    log "ERROR: Failed to import '${name}' (HTTP ${http_code}): ${body}"
    return 1
  fi
}

activate_workflow() {
  local workflow_id="$1"
  log "Activating workflow ID: ${workflow_id}"
  local response
  response=$(curl -s -w "\n%{http_code}" -X PATCH "${N8N_API_URL}/workflows/${workflow_id}" \
    -H "Content-Type: application/json" \
    -d '{"active": true}')

  local http_code
  http_code=$(echo "$response" | tail -n1)
  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    log "Activated workflow ${workflow_id}"
  else
    log "WARNING: Failed to activate workflow ${workflow_id} (HTTP ${http_code})"
  fi
}

create_credentials() {
  log "Creating credentials..."

  local -A creds=(
    ["Wazuh API"]='{"host": "'"${WAZUH_API_URL:-https://wazuh:55000}"'", "username": "'"${WAZUH_API_USER:-admin}"'", "password": "'"${WAZUH_API_PASSWORD:-changeme}"'"}'
    ["TheHive API"]='{"url": "'"${THEHIVE_URL:-http://thehive:9000}"'", "apiKey": "'"${THEHIVE_API_KEY:-changeme}"'"}'
    ["Cortex API"]='{"url": "'"${CORTEX_URL:-http://cortex:9001}"'", "apiKey": "'"${CORTEX_API_KEY:-changeme}"'"}'
    ["OpenCTI Token"]='{"url": "'"${OPENCTI_URL:-http://opencti:8080}"'", "token": "'"${OPENCTI_API_TOKEN:-changeme}"'"}'
    ["Slack Webhook"]='{"url": "'"${SLACK_WEBHOOK_URL:-}"'"}'
    ["LangGraph API"]='{"url": "'"${LANGGRAPH_URL:-http://langgraph:8000}"'"}'
  )

  for cred_name in "${!creds[@]}"; do
    local payload
    payload=$(jq -n \
      --arg type "${cred_name}" \
      --argjson data "${creds[$cred_name]}" \
      '{name: $type, type: $type, data: $data}')

    local response
    response=$(curl -s -w "\n%{http_code}" -X POST "${N8N_API_URL}/credentials" \
      -H "Content-Type: application/json" \
      -d "$payload")

    local http_code
    http_code=$(echo "$response" | tail -n1)
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
      log "Created credential: ${cred_name}"
    else
      log "WARNING: Failed to create credential '${cred_name}' (HTTP ${http_code})"
    fi
  done
}

set_environment_variables() {
  log "Setting environment variables..."

  local -A env_vars=(
    ["WAZUH_API_URL"]="${WAZUH_API_URL:-https://wazuh:55000}"
    ["THEHIVE_URL"]="${THEHIVE_URL:-http://thehive:9000}"
    ["CORTEX_URL"]="${CORTEX_URL:-http://cortex:9001}"
    ["OPENCTI_URL"]="${OPENCTI_URL:-http://opencti:8080}"
    ["LANGGRAPH_URL"]="${LANGGRAPH_URL:-http://langgraph:8000}"
    ["SLACK_WEBHOOK_URL"]="${SLACK_WEBHOOK_URL:-}"
  )

  for var_name in "${!env_vars[@]}"; do
    local payload
    payload=$(jq -n \
      --arg name "$var_name" \
      --arg value "${env_vars[$var_name]}" \
      '{name: $name, value: $value}')

    local response
    response=$(curl -s -w "\n%{http_code}" -X POST "${N8N_API_URL}/variables" \
      -H "Content-Type: application/json" \
      -d "$payload")

    local http_code
    http_code=$(echo "$response" | tail -n1)
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
      log "Set variable: ${var_name}"
    else
      log "WARNING: Failed to set variable '${var_name}' (HTTP ${http_code})"
    fi
  done
}

main() {
  log "=== n8n initialization starting ==="

  wait_for_n8n
  set_environment_variables
  create_credentials

  local import_count=0
  local fail_count=0

  if [[ ! -d "$WORKFLOW_DIR" ]]; then
    die "Workflow directory not found: ${WORKFLOW_DIR}"
  fi

  for workflow_file in "${WORKFLOW_DIR}"/*.json; do
    [[ -f "$workflow_file" ]] || continue
    local wf_id
    if wf_id=$(import_workflow "$workflow_file"); then
      if [[ -n "$wf_id" ]]; then
        activate_workflow "$wf_id"
      fi
      (( import_count++ ))
    else
      (( fail_count++ ))
    fi
  done

  log "=== n8n initialization complete ==="
  log "Workflows imported: ${import_count}"
  log "Workflows failed:   ${fail_count}"

  if (( fail_count > 0 )); then
    log "WARNING: Some workflows failed to import"
    exit 1
  fi

  log "All workflows imported and activated successfully."
}

main "$@"
