// =============================================================================
// Cobalto SOC/MDR — Benchmark Helpers
// =============================================================================
// Utility functions for k6 benchmarks: authentication, tagging, reporting.
// =============================================================================

import http from 'k6/http';
import { check, fail } from 'k6';
import { getBaseUrl, getHeaders } from './config.js';

/**
 * Authenticate with the console auth service and return a Bearer token.
 * Falls back to anonymous if auth service is unreachable.
 *
 * @param {string} username
 * @param {string} password
 * @returns {string} — Bearer token or empty string
 */
export function authenticate(username, password) {
  const url = `${getBaseUrl()}/api/auth/login`;
  const payload = JSON.stringify({
    username: username || 'testadmin',
    password: password || 'testpassword123',
  });
  const headers = { 'Content-Type': 'application/json' };

  const res = http.post(url, payload, { headers });
  if (res.status === 200) {
    try {
      const body = JSON.parse(res.body);
      return body.access_token || '';
    } catch (_) {
      return '';
    }
  }
  return '';
}

/**
 * Generate a tagged request ID for correlation across metrics.
 * Format: bench-{vu}-{iter}
 */
export function requestTag(vu, iter) {
  const v = vu !== undefined ? vu : __VU;
  const i = iter !== undefined ? iter : __ITER;
  return `bench-${String(v).padStart(3, '0')}-${String(i).padStart(5, '0')}`;
}

/**
 * Tagged check — wraps k6 check with benchmark metadata.
 */
export function benchCheck(res, name, checks, tags = {}) {
  return check(res, {
    [name]: (r) => {
      const allPass = Object.entries(checks).every(([key, fn]) => fn(r));
      if (!allPass) {
        console.warn(
          `[BENCHMARK] ${name} FAILED | VU=${__VU} ITER=${__ITER} ` +
          `status=${r.status} duration=${r.timings.duration}ms`
        );
      }
      return allPass;
    },
  }, { vu: __VU, iter: __ITER, ...tags });
}

/**
 * Compute threshold breach message.
 */
export function thresholdMessage(testName, metric, p95, threshold) {
  return `[THRESHOLD] ${testName}: p95(${metric}) = ${p95.toFixed(0)}ms ` +
         `exceeds threshold ${threshold}ms`;
}
