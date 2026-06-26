#!/bin/bash
set -euo pipefail

# Cortex Bootstrap Configuration for Cobalto SOC/MDR Platform
# Initializes Cortex with organization, analyzers, and responder configuration

CORTEX_URL="${CORTEX_URL:-http://localhost:9001}"
CORTEX_API="${CORTEX_URL}/api"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETRY_INTERVAL=5
MAX_RETRIES=60
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@cobalto.internal}"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
    exit 1
}

wait_for_cortex() {
    log "Waiting for Cortex to be ready at ${CORTEX_URL}..."
    local retries=0
    while [ $retries -lt $MAX_RETRIES ]; do
        if curl -sf "${CORTEX_API}/status" > /dev/null 2>&1; then
            log "Cortex is ready."
            return 0
        fi
        retries=$((retries + 1))
        log "Cortex not ready yet. Retry ${retries}/${MAX_RETRIES}..."
        sleep $RETRY_INTERVAL
    done
    error "Cortex failed to become ready after ${MAX_RETRIES} attempts."
}

initialize_cortex() {
    log "Checking if Cortex needs initialization..."

    local status
    status=$(curl -sf "${CORTEX_API}/status" | jq -r '.versions.Cortex // "unknown"')

    if [ "$status" = "unknown" ] || [ -z "$status" ]; then
        log "Cortex requires initial setup. Performing initialization..."
        perform_initial_setup
    else
        log "Cortex already initialized (version: ${status})."
    fi
}

perform_initial_setup() {
    log "Performing initial Cortex setup..."

    local setup_payload="{
        \"login\": \"admin\",
        \"password\": \"${ADMIN_PASSWORD:-Secret123!}\",
        \"organisation\": \"Cobalto SOC\",
        \"email\": \"${ADMIN_EMAIL}\"
    }"

    curl -sf -X POST "${CORTEX_API}/cortex/api/v1/user" \
        -H "Content-Type: application/json" \
        -d "$setup_payload" > /dev/null 2>&1 || \
        log "WARNING: Initial user setup may have failed"

    log "Initial setup completed."
}

get_api_key() {
    local login=$1
    local password=$2

    local response
    response=$(curl -sf -X POST "${CORTEX_API}/api/login" \
        -H "Content-Type: application/json" \
        -d "{\"login\":\"${login}\",\"password\":\"${password}\"}" 2>/dev/null)

    if [ -n "$response" ]; then
        echo "$response" | jq -r '.key // empty'
    else
        echo ""
    fi
}

create_organization() {
    log "Creating organization 'cobalto-soc'..."

    local org_payload='{
        "name": "cobalto-soc",
        "description": "Cobalto SOC/MDR Platform Organization",
        "roles": ["orgadmin", "analyst", "read"],
        "maxUsers": 50,
        "enabled": true
    }'

    curl -sf -X POST "${CORTEX_API}/api/organization" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${CORTEX_API_KEY}" \
        -d "$org_payload" > /dev/null 2>&1 || \
        log "WARNING: Organization may already exist"

    log "Organization created."
}

create_analyzer_account() {
    log "Creating analyzer service account..."

    local account_payload="{
        \"login\": \"analyzer-service\",
        \"name\": \"Analyzer Service Account\",
        \"email\": \"analyzer@cobalto.internal\",
        \"organization\": \"cobalto-soc\",
        \"roles\": [\"orgadmin\"],
        \"enabled\": true
    }"

    curl -sf -X POST "${CORTEX_API}/api/user" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${CORTEX_API_KEY}" \
        -d "$account_payload" > /dev/null 2>&1 || \
        log "WARNING: Analyzer account may already exist"

    log "Analyzer account created."
}

enable_analyzers() {
    log "Enabling analyzers..."

    local analyzer_payload
    analyzer_payload=$(cat "${SCRIPT_DIR}/cortex-analyzers.json" | jq '.analyzers')

    local analyzer_count=$(echo "$analyzer_payload" | jq 'length')
    for i in $(seq 0 $((analyzer_count - 1))); do
        local analyzer=$(echo "$analyzer_payload" | jq -r ".[$i]")
        local name=$(echo "$analyzer" | jq -r '.name')
        log "  Enabling analyzer: ${name}"

        curl -sf -X POST "${CORTEX_API}/api/analyzer" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${CORTEX_API_KEY}" \
            -d "$analyzer" > /dev/null 2>&1 || \
            log "  WARNING: Analyzer ${name} may already exist"
    done

    log "Analyzers enabled."
}

configure_analyzer_api_keys() {
    log "Configuring analyzer API keys..."

    local api_key="${VIRUSTOTAL_API_KEY:-}"
    if [ -n "$api_key" ]; then
        log "  Configuring VirusTotal API key..."
        curl -sf -X PUT "${CORTEX_API}/api/analyzer/VirusTotal_GetReport_3_1" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${CORTEX_API_KEY}" \
            -d "{\"configurationItems\":{\"apikey\":\"${api_key}\"}}" > /dev/null 2>&1 || \
            log "  WARNING: Failed to configure VirusTotal API key"
    fi

    api_key="${ABUSEIPDB_API_KEY:-}"
    if [ -n "$api_key" ]; then
        log "  Configuring AbuseIPDB API key..."
        curl -sf -X PUT "${CORTEX_API}/api/analyzer/AbuseIPDB_1_1" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${CORTEX_API_KEY}" \
            -d "{\"configurationItems\":{\"apikey\":\"${api_key}\"}}" > /dev/null 2>&1 || \
            log "  WARNING: Failed to configure AbuseIPDB API key"
    fi

    api_key="${SHODAN_API_KEY:-}"
    if [ -n "$api_key" ]; then
        log "  Configuring Shodan API key..."
        curl -sf -X PUT "${CORTEX_API}/api/analyzer/Shodan_Host_1_0" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${CORTEX_API_KEY}" \
            -d "{\"configurationItems\":{\"apikey\":\"${api_key}\"}}" > /dev/null 2>&1 || \
            log "  WARNING: Failed to configure Shodan API key"
    fi

    log "API keys configured."
}

configure_responders() {
    log "Configuring responder jobs..."

    local responder_config
    responder_config=$(cat "${SCRIPT_DIR}/cortex-analyzers.json" | jq '.responder_config')

    curl -sf -X PUT "${CORTEX_API}/api/config" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${CORTEX_API_KEY}" \
        -d "$responder_config" > /dev/null 2>&1 || \
        log "WARNING: Failed to configure responder settings"

    log "Responder configuration applied."
}

create_org_user() {
    local login=$1
    local name=$2
    local email=$3
    local role=$4

    log "  Creating user: ${login} (${role})"

    local user_payload="{
        \"login\": \"${login}\",
        \"name\": \"${name}\",
        \"email\": \"${email}\",
        \"organization\": \"cobalto-soc\",
        \"roles\": [\"${role}\"],
        \"enabled\": true
    }"

    curl -sf -X POST "${CORTEX_API}/api/user" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${CORTEX_API_KEY}" \
        -d "$user_payload" > /dev/null 2>&1 || \
        log "  WARNING: User ${login} may already exist"
}

create_responder_users() {
    log "Creating responder users..."

    create_org_user "soc-analyst" "SOC Analyst" "analyst@cobalto.internal" "analyst"
    create_org_user "senior-analyst" "Senior Analyst" "senior.analyst@cobalto.internal" "orgadmin"
    create_org_user "soc-admin" "SOC Administrator" "socadmin@cobalto.internal" "orgadmin"

    log "Responder users created."
}

enable_responders() {
    log "Enabling built-in responders..."

    local responders=(
        "MISP_1_0"
        "DNS_1_0"
        "URLhaus_1_0"
        "Telegram_1_0"
        "PagerDuty_1_0"
        "Slack_1_0"
        "ServiceNow_1_0"
    )

    for responder in "${responders[@]}"; do
        log "  Enabling responder: ${responder}"
        curl -sf -X POST "${CORTEX_API}/api/responder" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${CORTEX_API_KEY}" \
            -d "{\"name\":\"${responder}\",\"enabled\":true}" > /dev/null 2>&1 || \
            log "  WARNING: Responder ${responder} may not be available"
    done

    log "Responders enabled."
}

verify_analyzers() {
    log "Verifying analyzer status..."

    local response
    response=$(curl -sf "${CORTEX_API}/api/analyzer" \
        -H "Authorization: Bearer ${CORTEX_API_KEY}" 2>/dev/null)

    if [ -n "$response" ]; then
        local count=$(echo "$response" | jq 'length')
        log "  Total analyzers available: ${count}"
        echo "$response" | jq -r '.[] | "    - \(.name) (v\(.version // "unknown")) [\(.dataTypeList | join(", "))]"'
    fi

    log "Analyzer verification completed."
}

generate_api_key_for_thehive() {
    log "Generating API key for TheHive integration..."

    local key_response
    key_response=$(curl -sf -X POST "${CORTEX_API}/api/user/cobalto-soc/apikey" \
        -H "Authorization: Bearer ${CORTEX_API_KEY}" 2>/dev/null)

    if [ -n "$key_response" ]; then
        local api_key=$(echo "$key_response" | jq -r '.key // empty')
        if [ -n "$api_key" ]; then
            log "  TheHive API key generated. Store this securely:"
            log "  CORTEX_API_KEY=${api_key}"
        fi
    fi

    log "API key generation completed."
}

main() {
    log "=== Cortex Bootstrap for Cobalto SOC/MDR Platform ==="
    log "Target: ${CORTEX_URL}"

    wait_for_cortex
    initialize_cortex

    if [ -z "${CORTEX_API_KEY:-}" ]; then
        log "No API key provided. Attempting to generate..."
        CORTEX_API_KEY=$(get_api_key "admin" "${ADMIN_PASSWORD:-Secret123!}")
        if [ -z "$CORTEX_API_KEY" ]; then
            error "Failed to obtain API key. Please set CORTEX_API_KEY environment variable."
        fi
    fi

    create_organization
    create_analyzer_account
    enable_analyzers
    configure_analyzer_api_keys
    configure_responders
    create_responder_users
    enable_responders
    verify_analyzers
    generate_api_key_for_thehive

    log "=== Cortex bootstrap completed successfully ==="
}

main "$@"
