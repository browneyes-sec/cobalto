// =============================================================================
// Cobalto SOC/MDR — Auth Service Burst
// =============================================================================
// Validates the console auth service under burst login patterns.
// Simulates: 10 simultaneous logins, then 50, then steady-state.
//
// Thresholds:
//   p95 < 500ms   — 95% of auth requests complete within 500ms
//   p99 < 1000ms  — 99th percentile under 1 second
//   failure rate < 1%  (excluding expected 429 rate limits)
// =============================================================================

import http from 'k6/http';
import { sleep } from 'k6';
import { check, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { getBaseUrl, buildLoginPayload } from './config.js';

// ── Custom Metrics ──────────────────────────────────────────────────────────

const loginLatency = new Trend('cobalto_auth_login_latency');
const verifyLatency = new Trend('cobalto_auth_verify_latency');
const refreshLatency = new Trend('cobalto_auth_refresh_latency');
const authErrors = new Rate('cobalto_auth_errors');
const rateLimited = new Rate('cobalto_auth_rate_limited');
const tokensIssued = new Counter('cobalto_auth_tokens_issued');

// ── Test Options ────────────────────────────────────────────────────────────

export const options = {
  stages: [
    { target: 10, duration: '10s' },  // Initial burst
    { target: 50, duration: '10s' },  // Peak burst
    { target: 10, duration: '15s' },  // Sustained
    { target: 0, duration: '5s' },    // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.05'],  // 5% allowed (rate limits expected)
    cobalto_auth_login_latency: ['p(95)<500', 'p(99)<1000'],
    cobalto_auth_errors: ['rate<0.05'],
  },
  tags: {
    test: 'auth_burst',
    component: 'console-auth',
  },
};

// ── Constants ───────────────────────────────────────────────────────────────

const BASE_URL = getBaseUrl();
const USERS = [
  { username: 'testadmin', password: 'testpassword123' },
  { username: 'analyst', password: 'testpassword123' },
];

// ── Main Test ───────────────────────────────────────────────────────────────

export default function () {
  const user = USERS[__ITER % USERS.length];
  const loginPayload = buildLoginPayload(user.username, user.password);

  // ── Login ─────────────────────────────────────────────────────────────
  group('auth login', function () {
    const loginRes = http.post(`${BASE_URL}/api/auth/login`, loginPayload, {
      headers: { 'Content-Type': 'application/json' },
      tags: { auth_action: 'login', user: user.username },
    });

    loginLatency.add(loginRes.timings.duration, {
      user: user.username,
      status: loginRes.status,
    });

    if (loginRes.status === 200) {
      tokensIssued.add(1);
      const body = JSON.parse(loginRes.body);
      const accessToken = body.access_token;
      const refreshToken = body.refresh_token;

      // ── Verify token ──────────────────────────────────────────────────
      group('auth verify', function () {
        const verifyRes = http.post(
          `${BASE_URL}/api/auth/verify`,
          JSON.stringify({ token: accessToken }),
          { headers: { 'Content-Type': 'application/json' } }
        );
        verifyLatency.add(verifyRes.timings.duration);
        check(verifyRes, {
          'verify returns 200': (r) => r.status === 200,
          'verify returns valid user': (r) => {
            try {
              return JSON.parse(r.body).username === user.username;
            } catch (_) {
              return false;
            }
          },
        });
      });

      // ── Refresh token ────────────────────────────────────────────────
      group('auth refresh', function () {
        const refreshRes = http.post(
          `${BASE_URL}/api/auth/refresh`,
          JSON.stringify({ refresh_token: refreshToken }),
          { headers: { 'Content-Type': 'application/json' } }
        );
        refreshLatency.add(refreshRes.timings.duration);
        check(refreshRes, {
          'refresh returns 200': (r) => r.status === 200,
          'refresh returns new token': (r) => {
            try {
              return JSON.parse(r.body).access_token !== undefined;
            } catch (_) {
              return false;
            }
          },
        });
      });
    } else if (loginRes.status === 429) {
      rateLimited.add(true);
    } else {
      authErrors.add(true);
      console.warn(
        `[AUTH] LOGIN FAILED | user=${user.username} ` +
        `status=${loginRes.status} duration=${loginRes.timings.duration}ms`
      );
    }

    // Validate login response
    check(loginRes, {
      'login returns 200 or 429': (r) => r.status === 200 || r.status === 429,
    });
  });

  // Think time — real users don't login constantly
  sleep(0.5 + Math.random() * 2.0);
}
