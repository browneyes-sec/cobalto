// =============================================================================
// Cobalto SOC/MDR — Health & Readiness Probe Performance
// =============================================================================
// Verifies that lightweight endpoints (/health, /ready, /metrics) respond
// quickly under high concurrency. These are polled frequently by K8s and
// monitoring systems, so latency must be minimal.
//
// Thresholds:
//   p95 < 100ms   — 95% of requests complete within 100ms
//   p99 < 200ms   — 99th percentile under 200ms
//   failure rate = 0%  (these must always succeed)
// =============================================================================

import http from 'k6/http';
import { check, group } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { getBaseUrl, getHeaders } from './config.js';

// ── Custom Metrics (per endpoint) ───────────────────────────────────────────

const healthLatency = new Trend('cobalto_health_latency');
const readyLatency = new Trend('cobalto_ready_latency');
const metricsLatency = new Trend('cobalto_metrics_latency');
const errorRate = new Rate('cobalto_health_errors');

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    { target: 10, duration: '10s' },   // Warm-up
    { target: 50, duration: '20s' },   // High concurrency
    { target: 100, duration: '20s' },  // Burst (K8s probes + monitoring)
    { target: 0, duration: '5s' },     // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<100', 'p(99)<200'],
    http_req_failed: ['rate<0.001'],
    cobalto_health_latency: ['p(95)<100', 'p(99)<200'],
    cobalto_ready_latency: ['p(95)<100', 'p(99)<200'],
    cobalto_metrics_latency: ['p(99)<500'],
    cobalto_health_errors: ['rate<0.001'],
  },
  tags: {
    test: 'health_check',
    component: 'langgraph-agent',
  },
};

// ── Setup ───────────────────────────────────────────────────────────────────

const BASE_URL = getBaseUrl();
const HEADERS = getHeaders();

export function setup() {
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'setup: service is reachable': (r) => r.status === 200,
  });
  return { startTime: new Date().toISOString() };
}

// ── Main Test ───────────────────────────────────────────────────────────────

export default function () {
  // ── /health ──────────────────────────────────────────────────────────
  group('endpoint /health', function () {
    const res = http.get(`${BASE_URL}/health`, {
      headers: HEADERS,
      tags: { endpoint: '/health' },
    });
    healthLatency.add(res.timings.duration);
    check(res, {
      'health returns 200': (r) => r.status === 200,
      'health returns healthy status': (r) => {
        try {
          return JSON.parse(r.body).status === 'healthy';
        } catch (_) {
          return false;
        }
      },
    });
    if (res.status !== 200) {
      errorRate.add(true);
    }
  });

  // ── /ready ───────────────────────────────────────────────────────────
  group('endpoint /ready', function () {
    const res = http.get(`${BASE_URL}/ready`, {
      headers: HEADERS,
      tags: { endpoint: '/ready' },
    });
    readyLatency.add(res.timings.duration);
    check(res, {
      'ready returns 200': (r) => r.status === 200,
      'ready returns ready status': (r) => {
        try {
          return JSON.parse(r.body).status === 'ready';
        } catch (_) {
          return false;
        }
      },
    });
    if (res.status !== 200) {
      errorRate.add(true);
    }
  });

  // ── /metrics (Prometheus) ────────────────────────────────────────────
  group('endpoint /metrics', function () {
    const res = http.get(`${BASE_URL}/metrics`, {
      headers: HEADERS,
      tags: { endpoint: '/metrics' },
    });
    metricsLatency.add(res.timings.duration);
    check(res, {
      'metrics returns 200': (r) => r.status === 200,
      'metrics contains prometheus data': (r) => {
        return r.body && r.body.includes('cobalto_');
      },
    });
    if (res.status !== 200) {
      errorRate.add(true);
    }
  });
}
