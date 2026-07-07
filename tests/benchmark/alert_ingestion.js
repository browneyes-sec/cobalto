// =============================================================================
// Cobalto SOC/MDR — Alert Ingestion Throughput
// =============================================================================
// Measures how many alert analysis requests the agent pipeline can handle
// under sustained load. Ramps from 1 → 10 → 20 VUs, each for 30s.
//
// Thresholds:
//   p95 < 5000ms  — 95% of requests complete within 5 seconds
//   p99 < 10000ms — 99% of requests complete within 10 seconds
//   failure rate < 1%
// =============================================================================

import http from 'k6/http';
import { sleep } from 'k6';
import { check } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { getBaseUrl, getHeaders, buildAlertPayload } from './config.js';

// ── Custom Metrics ──────────────────────────────────────────────────────────

const ingestionLatency = new Trend('cobalto_ingestion_latency');
const ingestionRate = new Rate('cobalto_ingestion_rate');
const validationErrors = new Rate('cobalto_validation_errors');

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    { target: 1, duration: '10s' },   // Warm-up: single user
    { target: 5, duration: '20s' },   // Ramp to moderate load
    { target: 10, duration: '30s' },  // Moderate load
    { target: 20, duration: '30s' },  // Peak load
    { target: 5, duration: '10s' },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000', 'p(99)<10000'],
    http_req_failed: ['rate<0.01'],
    cobalto_ingestion_latency: ['p(95)<5000'],
    cobalto_validation_errors: ['rate<0.01'],
  },
  tags: {
    test: 'alert_ingestion',
    component: 'langgraph-agent',
  },
};

// ── Setup ───────────────────────────────────────────────────────────────────

const BASE_URL = getBaseUrl();
const HEADERS = getHeaders();

export function setup() {
  // Verify service is reachable before running load
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'setup: health check passes': (r) => r.status === 200,
  });

  return {
    startTime: new Date().toISOString(),
    targetUrl: BASE_URL,
  };
}

// ── Main Test ───────────────────────────────────────────────────────────────

export default function (data) {
  // Each VU gets its own alert ID for traceability
  const alertId = `BENCH-INGEST-${String(__VU).padStart(3, '0')}-${String(__ITER).padStart(5, '0')}`;
  const payload = buildAlertPayload(alertId, 1); // LOW severity

  const res = http.post(`${BASE_URL}/agent/analyze`, payload, {
    headers: HEADERS,
    tags: { alert_id: alertId, vu: __VU, iter: __ITER },
  });

  // Record latency
  ingestionLatency.add(res.timings.duration, {
    vu: __VU,
    iter: __ITER,
    status: res.status,
  });

  // Validate response
  const passed = check(res, {
    'status is 200': (r) => r.status === 200,
    'has incident_id': (r) => {
      try {
        return JSON.parse(r.body).incident_id !== '';
      } catch (_) {
        return false;
      }
    },
    'has final_report': (r) => {
      try {
        return JSON.parse(r.body).final_report !== '';
      } catch (_) {
        return false;
      }
    },
  });

  if (passed) {
    ingestionRate.add(true);
  } else {
    validationErrors.add(true);
    console.warn(
      `[INGESTION] FAILED | VU=${__VU} ITER=${__ITER} ` +
      `status=${res.status} duration=${res.timings.duration}ms`
    );
  }

  // Think time between requests (randomized 100-500ms)
  sleep(0.1 + Math.random() * 0.4);
}

// ── Teardown ─────────────────────────────────────────────────────────────────

export function teardown(data) {
  console.log(`[INGESTION] Test complete. Started: ${data.startTime}`);
  console.log(`[INGESTION] Target: ${data.targetUrl}`);
}
