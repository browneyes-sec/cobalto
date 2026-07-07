// =============================================================================
// Cobalto SOC/MDR — Benchmark Configuration
// =============================================================================
// Shared configuration for all k6 benchmark scripts.
//
// Environment variables (overridable):
//   COBALTO_BENCHMARK_URL   — Base URL (default: http://localhost:8000)
//   COBALTO_API_KEY         — X-API-Key for auth (default: empty = no auth)
// =============================================================================

const BASE_URL = __ENV.COBALTO_BENCHMARK_URL || 'http://localhost:8000';
const API_KEY = __ENV.COBALTO_API_KEY || '';

export function getBaseUrl() {
  return BASE_URL;
}

export function getHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  if (API_KEY) {
    headers['X-API-Key'] = API_KEY;
  }
  return headers;
}

/**
 * Build a Wazuh-style alert payload.
 * @param {string} alertId — unique alert ID (e.g. "BENCH-00042")
 * @param {number} level   — alert level (1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL)
 */
export function buildAlertPayload(alertId, level = 1) {
  return JSON.stringify({
    alert_id: alertId,
    rule_id: 800300,
    rule_description: 'SSH login from unknown user',
    alert_level: level,
    source_ip: '10.0.0.50',
    dest_ip: '10.0.0.10',
    agent_name: 'ssh-server-01',
    timestamp: new Date().toISOString(),
    raw_log: 'sshd[9999]: Failed password for root from 10.0.0.50 port 44222 ssh2',
  });
}

/**
 * Build a login request payload for the console auth service.
 */
export function buildLoginPayload(username, password) {
  return JSON.stringify({
    username: username || 'testadmin',
    password: password || 'testpassword123',
  });
}
