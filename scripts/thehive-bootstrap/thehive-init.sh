#!/bin/bash
set -euo pipefail

# TheHive Bootstrap Configuration for Cobalto SOC/MDR Platform
# Initializes TheHive with templates, custom fields, users, and dashboards

THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
THEHIVE_API="${THEHIVE_URL}/api"
THEHIVE_VERSION="5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETRY_INTERVAL=5
MAX_RETRIES=60

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
    exit 1
}

wait_for_thehive() {
    log "Waiting for TheHive to be ready at ${THEHIVE_URL}..."
    local retries=0
    while [ $retries -lt $MAX_RETRIES ]; do
        if curl -sf "${THEHIVE_URL}/api/v1/status" > /dev/null 2>&1; then
            log "TheHive is ready."
            return 0
        fi
        retries=$((retries + 1))
        log "TheHive not ready yet. Retry ${retries}/${MAX_RETRIES}..."
        sleep $RETRY_INTERVAL
    done
    error "TheHive failed to become ready after ${MAX_RETRIES} attempts."
}

wait_for_cortex() {
    local cortex_url="${CORTEX_URL:-http://localhost:9001}"
    log "Waiting for Cortex to be ready at ${cortex_url}..."
    local retries=0
    while [ $retries -lt $MAX_RETRIES ]; do
        if curl -sf "${cortex_url}/api/status" > /dev/null 2>&1; then
            log "Cortex is ready."
            return 0
        fi
        retries=$((retries + 1))
        log "Cortex not ready yet. Retry ${retries}/${MAX_RETRIES}..."
        sleep $RETRY_INTERVAL
    done
    log "WARNING: Cortex not available. Continuing without analyzer integration."
}

create_custom_fields() {
    log "Creating custom field definitions..."

    local fields=(
        '{"name":"mitre_technique","description":"MITRE ATT&CK Technique ID and description","type":"string","options":[]}'
        '{"name":"detection_source","description":"Source system that generated the detection","type":"string","options":["Wazuh SIEM","EDR","CSPM","CloudTrail","User Report","UEBA"]}'
        '{"name":"incident_severity","description":"Severity assessment from initial triage","type":"string","options":["Critical","High","Medium","Low","Informational"]}'
        '{"name":"source_ip","description":"Source IP address of the attacker","type":"string","options":[]}'
        '{"name":"affected_assets","description":"Assets affected by the incident","type":"string","options":[]}'
        '{"name":"false_positive_assessment","description":"Assessment of false positive likelihood","type":"string","options":["Confirmed Malicious","Likely Malicious","Requires Validation","Likely False Positive","Confirmed False Positive"]}'
        '{"name":"cloud_provider","description":"Cloud service provider","type":"string","options":["AWS","Azure","GCP","Multi-Cloud"]}'
        '{"name":"malware_family","description":"Identified malware family name","type":"string","options":[]}'
        '{"name":"file_hash","description":"Hash of malicious file (MD5/SHA1/SHA256)","type":"string","options":[]}'
        '{"name":"phishing_url","description":"URL associated with phishing campaign","type":"string","options":[]}'
        '{"name":"sender_email","description":"Sender email address","type":"string","options":[]}'
        '{"name":"activity_description","description":"Description of suspicious user activity","type":"string","options":[]}'
        '{"name":"data_access_level","description":"Level of data access by compromised account","type":"string","options":["Public","Internal","Confidential","Restricted","Top Secret"]}'
        '{"name":"playbook_used","description":"SOC playbook applied during investigation","type":"string","options":["Incident Response","Malware Analysis","Phishing Response","Insider Threat","Cloud Security"]}'
        '{"name":"containment_status","description":"Current status of incident containment","type":"string","options":["Not Contained","Partially Contained","Fully Contained","Escalated"]}'
    )

    for field_json in "${fields[@]}"; do
        local name=$(echo "$field_json" | jq -r '.name')
        log "  Creating custom field: ${name}"
        curl -sf -X POST "${THEHIVE_API}/v1/customField" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
            -d "$field_json" > /dev/null 2>&1 || \
            log "  WARNING: Field ${name} may already exist"
    done

    log "Custom fields created."
}

create_case_templates() {
    log "Creating case templates..."

    local templates_file="${SCRIPT_DIR}/thehive-templates.json"
    if [ ! -f "$templates_file" ]; then
        error "Templates file not found: ${templates_file}"
    fi

    local template_count=$(jq '.templates | length' "$templates_file")
    for i in $(seq 0 $((template_count - 1))); do
        local template=$(jq -r ".templates[$i]" "$templates_file")
        local title=$(echo "$template" | jq -r '.title')
        log "  Creating template: ${title}"

        curl -sf -X POST "${THEHIVE_API}/v1/caseTemplate" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
            -d "$template" > /dev/null 2>&1 || \
            log "  WARNING: Template ${title} may already exist"
    done

    log "Case templates created."
}

create_responder_accounts() {
    log "Creating responder accounts..."

    local users=(
        '{"login":"analyst","name":"SOC Analyst","email":"analyst@cobalto.internal","roles":["analyst"],"organization":"cobalto-soc"}'
        '{"login":"senior_analyst","name":"Senior SOC Analyst","email":"senior.analyst@cobalto.internal","roles":["analyst","admin"],"organization":"cobalto-soc"}'
        '{"login":"admin","name":"SOC Administrator","email":"admin@cobalto.internal","roles":["admin","analyst","orgadmin"],"organization":"cobalto-soc"}'
    )

    for user_json in "${users[@]}"; do
        local login=$(echo "$user_json" | jq -r '.login')
        log "  Creating user: ${login}"

        curl -sf -X POST "${THEHIVE_API}/v1/user" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
            -d "$user_json" > /dev/null 2>&1 || \
            log "  WARNING: User ${login} may already exist"
    done

    log "Responder accounts created."
}

create_dashboard_widgets() {
    log "Creating dashboard widgets..."

    local widgets=(
        '{"title":"Open Cases by Severity","description":"Distribution of open cases by severity level","type":"case_severity","query":{"status":"Open"}}'
        '{"title":"Cases Last 24 Hours","description":"Cases created in the last 24 hours","type":"case_count","query":{"createdAt":">-24h"}}'
        '{"title":"Top MITRE Techniques","description":"Most frequently observed MITRE ATT&CK techniques","type":"case_metrics","query":{"customFields.mitre_technique":"*"},"groupBy":"customFields.mitre_technique"}'
        '{"title":"Cases by Detection Source","description":"Cases grouped by detection source","type":"case_metrics","query":{},"groupBy":"customFields.detection_source"}'
        '{"title":"Mean Time to Triage","description":"Average time from case creation to first action","type":"case_metrics","query":{},"metric":"timeToTriage"}'
        '{"title":"Analyst Workload","description":"Active cases per analyst","type":"case_metrics","query":{"status":"Open"},"groupBy":"assignee"}'
        '{"title":"False Positive Rate","description":"Percentage of cases classified as false positive","type":"case_metrics","query":{},"groupBy":"customFields.false_positive_assessment"}'
        '{"title":"Containment Status","description":"Cases by containment status","type":"case_metrics","query":{},"groupBy":"customFields.containment_status"}'
    )

    for widget_json in "${widgets[@]}"; do
        local title=$(echo "$widget_json" | jq -r '.title')
        log "  Creating widget: ${title}"

        curl -sf -X POST "${THEHIVE_API}/v1/dashboard" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
            -d "$widget_json" > /dev/null 2>&1 || \
            log "  WARNING: Widget ${title} may already exist"
    done

    log "Dashboard widgets created."
}

configure_cortex_integration() {
    log "Configuring Cortex integration..."

    local cortex_url="${CORTEX_URL:-http://localhost:9001}"
    local cortex_config="{
        \"url\": \"${cortex_url}\",
        \"apiKey\": \"${CORTEX_API_KEY:-}\",
        \"organization\": \"cobalto-soc\"
    }"

    curl -sf -X PUT "${THEHIVE_API}/v1/config/connector/cortex" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
        -d "$cortex_config" > /dev/null 2>&1 || \
        log "WARNING: Failed to configure Cortex integration"

    log "Cortex integration configured."
}

create_observable_types() {
    log "Creating custom observable types..."

    local types=(
        '{"name":"aws-access-key","description":"AWS Access Key ID","dataType":"other"}'
        '{"name":"aws-account-id","description":"AWS Account ID","dataType":"other"}'
        '{"name":"gcp-project","description":"GCP Project ID","dataType":"other"}'
        '{"name":"azure-tenant","description":"Azure Tenant ID","dataType":"other"}'
        '{"name":"container-id","description":"Docker/Kubernetes container ID","dataType":"other"}'
        '{"name":"pod-name","description":"Kubernetes pod name","dataType":"other"}'
        '{"name":"k8s-namespace","description":"Kubernetes namespace","dataType":"other"}'
    )

    for type_json in "${types[@]}"; do
        local name=$(echo "$type_json" | jq -r '.name')
        log "  Creating observable type: ${name}"
        curl -sf -X POST "${THEHIVE_API}/v1/observableType" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
            -d "$type_json" > /dev/null 2>&1 || \
            log "  WARNING: Observable type ${name} may already exist"
    done

    log "Observable types created."
}

main() {
    log "=== TheHive Bootstrap for Cobalto SOC/MDR Platform ==="
    log "Target: ${THEHIVE_URL}"

    wait_for_thehive
    wait_for_cortex

    create_custom_fields
    create_case_templates
    create_responder_accounts
    create_dashboard_widgets
    configure_cortex_integration
    create_observable_types

    log "=== TheHive bootstrap completed successfully ==="
}

main "$@"
