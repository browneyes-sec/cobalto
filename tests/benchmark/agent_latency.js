// =============================================================================
// Cobalto SOC/MDR — Agent Pipeline Latency
// =============================================================================
// Measures end-to-end latency for the agent pipeline at different severity
// levels. Runs 5 constant VUs for 60s to establish steady-state latency.
//
// Thresholds:
//   p50 < 2000ms  — median latency under 2 seconds
//   p95 < 8000ms  — 95% of requests complete within 8 seconds
//   p99 < 15000ms — 99th percentile under 15 seconds
//   failure rate < 1%
// =============================================================================

import http from 'k6/http';
import { sleep } from 'k6';
import { check } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { getBaseUrl, getHeaders, buildAlertPayload } from './config.js';

// ── Custom Metrics (per severity) ───────────────────────────────────────────

const lowLatency = new Trend('cobalto_latency_low');
const medLatency = new Trend('cobalto_latency_medium');
const allLatency = new Trend('cobalto_latency_all');
const errorRate = new Rate('cobalto_latency_errors');
const timeouts = new Rate('cobalto_latency_timeouts');

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    { target: 5, duration: '10s' },  // Warm-up
    { target: 5, duration: '60s' },  // Steady state
    { target: 0, duration: '5s' },   // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(50)<2000', 'p(95)<8000', 'p(99)<15000'],
    http_req_failed: ['rate<0.01'],
    cobalto_latency_low: ['p(95)<5000'],
    cobalto_latency_medium: ['p(95)<10000'],
    cobalto_latency_all: ['p(50)<2000', 'p(95)<8000'],
  },
  tags: {
    test: 'agent_latency',
    component: 'langgraph-agent',
  },
};

// ── Setup ───────────────────────────────────────────────────────────────────

const BASE_URL = getBaseUrl();
const HEADERS = getHeaders();
const SEVERITY_LEVELS = [1, 2]; // LOW, MEDIUM (HIGH loops forever without approval)

export function setup() {
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'setup: health check passes': (r) => r.status === 200,
  });

  return { startTime: new Date().toISOString() };
}

// ── Main Test ───────────────────────────────────────────────────────────────

export default function (data) {
  // Round-robin through severity levels so each gets ~equal samples
  const severityIdx = __ITER % SEVERITY_LEVELS.length;
  const level = SEVERITY_LEVELS[severityIdx];
  const severityLabel = level === 1 ? 'LOW' : 'MEDIUM';

  const alertId = `BENCH-LAT-${severityLabel}-${String(__VU).padStart(3, '0')}-${String(__ITER).padStart(5, '0')}`;
  const payload = buildAlertPayload(alertId, level);

  const res = http.post(`${BASE_URL}/agent/analyze`, payload, {
    headers: HEADERS,
    tags: {
      alert_id: alertId,
      severity: severityLabel,
      vu: __VU,
      iter: __ITER,
    },
  });

  // Record by severity
  if (level === 1) {
    lowLatency.add(res.timings.duration);
  } else {
    medLatency.add(res.timings.duration);
  }
  allLatency.add(res.timings.duration);

  // Error tracking
  if (res.status === 429) {
    timeouts.add(true);
  } else if (res.status !== 200) {
    errorRate.add(true);
    console.warn(
      `[LATENCY] FAILED | severity=${severityLabel} VU=${__VU} ` +
      `ITER=${__ITER} status=${res.status} duration=${res.timings.duration}ms`
    );
  }

  // Validate
  check(res, {
    'status is 200': (r) => r.status === 200,
    'severity matches input': (r) => {
      try {
        return JSON.parse(r.body).severity === severityLabel;
      } catch (_) {
        return false;
      }
    },
    'response actions present': (r) => {
      try {
        return Array.isArray(JSON.parse(r.body).response_actions);
      } catch (_) {
        return false;
      }
    },
  });

  // Moderate think time — agents take real work
  sleep(0.5 + Math.random() * 1.0);
}

// ── Teardown ────────────────────────────────────────────────────────────────

export function teardown(data) {
  console.log(`[LATENCY] Test complete. Started: ${data.startTime}`);
}
