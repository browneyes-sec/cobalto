#!/usr/bin/env bash
set -euo pipefail

N8N_API_URL="${N8N_API_URL:-http://localhost:5678/api/v1}"
WORKFLOW_DIR="${1:-/workflows/n8n}"

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"; }
die() { log "FATAL: $*"; exit 1; }

validate_workflow() {
  local file="$1"
  local filename
  filename=$(basename "$file")

  if ! [[ -f "$file" ]]; then
    log "ERROR: File not found: ${file}"
    return 1
  fi

  if ! jq empty "$file" 2>/dev/null; then
    log "ERROR: Invalid JSON: ${file}"
    return 1
  fi

  local name
  name=$(jq -r '.name // empty' "$file")
  if [[ -z "$name" ]]; then
    log "ERROR: Workflow missing 'name' field: ${file}"
    return 1
  fi

  local has_nodes
  has_nodes=$(jq 'has("nodes")' "$file")
  if [[ "$has_nodes" != "true" ]]; then
    log "ERROR: Workflow missing 'nodes' array: ${file}"
    return 1
  fi

  local node_count
  node_count=$(jq '.nodes | length' "$file")
  if (( node_count == 0 )); then
    log "ERROR: Workflow has no nodes: ${file}"
    return 1
  fi

  log "VALID: ${filename} (name: '${name}', nodes: ${node_count})"
  return 0
}

import_workflow() {
  local file="$1"
  local filename
  filename=$(basename "$file" .json)

  log "Importing: ${filename}"
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
    workflow_id=$(echo "$body" | jq -r '.id // "unknown"')
    log "SUCCESS: Imported '${filename}' (ID: ${workflow_id})"
    return 0
  else
    log "ERROR: Failed to import '${filename}' (HTTP ${http_code})"
    log "  Response: ${body}"
    return 1
  fi
}

activate_workflow() {
  local workflow_id="$1"
  local response
  response=$(curl -s -w "\n%{http_code}" -X PATCH "${N8N_API_URL}/workflows/${workflow_id}" \
    -H "Content-Type: application/json" \
    -d '{"active": true}')

  local http_code
  http_code=$(echo "$response" | tail -n1)
  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    log "Activated workflow ${workflow_id}"
  else
    log "WARNING: Failed to activate workflow ${workflow_id}"
  fi
}

main() {
  if [[ ! -d "$WORKFLOW_DIR" ]]; then
    die "Directory not found: ${WORKFLOW_DIR}"
  fi

  log "Importing workflows from: ${WORKFLOW_DIR}"

  local files
  files=("${WORKFLOW_DIR}"/*.json)

  if [[ ! -f "${files[0]}" ]]; then
    die "No JSON files found in ${WORKFLOW_DIR}"
  fi

  log "--- Validating workflows ---"
  local valid=0
  local invalid=0
  for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    if validate_workflow "$file"; then
      (( valid++ ))
    else
      (( invalid++ ))
    fi
  done

  log "--- Validation complete: ${valid} valid, ${invalid} invalid ---"

  if (( invalid > 0 )); then
    die "Aborting due to invalid workflows. Fix errors above and retry."
  fi

  log "--- Importing workflows ---"
  local imported=0
  local failed=0
  for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    if import_workflow "$file"; then
      (( imported++ ))
    else
      (( failed++ ))
    fi
  done

  log "=== Import complete: ${imported} imported, ${failed} failed ==="

  if (( failed > 0 )); then
    exit 1
  fi

  log "Done."
}

main
