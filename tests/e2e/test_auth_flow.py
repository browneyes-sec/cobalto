"""
E2E Tests: Authentication Flow

Verifies the complete JWT authentication lifecycle:
  - Login with valid credentials
  - Access token verification
  - Protected endpoint access
  - Token refresh with rotation
  - Logout and revocation
  - Rate limiting on login

Requires: console-auth service deployed and configured with test users.
"""

import os
import pytest
import httpx
from conftest import AUTH_URL


AUTH_USER = os.getenv("COBALTO_E2E_USER", "testadmin")
AUTH_PASS = os.getenv("COBALTO_E2E_PASS", "")


@pytest.mark.auth
class TestLogin:
    """POST /auth/login — credential verification and token issuance."""

    def test_login_with_valid_credentials(self, http_client: httpx.Client):
        """Valid username and password should return access + refresh tokens."""
        if not AUTH_PASS:
            pytest.skip("COBALTO_E2E_PASS not set")

        resp = http_client.post(
            f"{AUTH_URL}/login",
            json={"username": AUTH_USER, "password": AUTH_PASS},
        )
        assert resp.status_code == 200
        data = resp.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0
        assert data["user"]["username"] == AUTH_USER

        # Verify token is a JWT with 3 parts
        parts = data["access_token"].split(".")
        assert len(parts) == 3, "Access token is not a valid JWT"

    def test_login_with_wrong_password(self, http_client: httpx.Client):
        """Invalid password should return 401 without revealing user existence."""
        resp = http_client.post(
            f"{AUTH_URL}/login",
            json={"username": "nonexistent", "password": "wrongpass"},
        )
        assert resp.status_code == 401
        data = resp.json()
        # Generic error message — don't reveal which field is wrong
        assert "invalid_credentials" in str(data)

    def test_login_with_empty_username(self, http_client: httpx.Client):
        """Empty username should return 422 validation error."""
        resp = http_client.post(
            f"{AUTH_URL}/login",
            json={"username": "", "password": "test"},
        )
        assert resp.status_code == 422

    def test_login_rate_limiting(self, http_client: httpx.Client):
        """Rapid failed logins should trigger rate limiting."""
        if not AUTH_PASS:
            pytest.skip("COBALTO_E2E_PASS not set")

        rate_limited = False
        for _ in range(15):
            resp = http_client.post(
                f"{AUTH_URL}/login",
                json={"username": AUTH_USER, "password": "wrong-password"},
            )
            if resp.status_code == 429:
                rate_limited = True
                data = resp.json()
                assert "rate_limit_exceeded" in str(data)
                break

        assert rate_limited, "Rate limiting was not triggered after 15 attempts"


@pytest.mark.auth
class TestTokenVerification:
    """GET /auth/verify — access token validation."""

    def test_verify_valid_token(self, http_client: httpx.Client, auth_token: str):
        """A valid access token should return user info."""
        headers = {"Authorization": f"Bearer {auth_token}"}
        resp = http_client.get(f"{AUTH_URL}/verify", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert "username" in data
        assert "role" in data

    def test_verify_no_token(self, http_client: httpx.Client):
        """Missing Authorization header should return 401."""
        resp = http_client.get(f"{AUTH_URL}/verify")
        assert resp.status_code == 401

    def test_verify_expired_token(self, http_client: httpx.Client):
        """An expired token should return 401."""
        headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNTAwMDAwMDAwfQ.invalid"}
        resp = http_client.get(f"{AUTH_URL}/verify", headers=headers)
        assert resp.status_code == 401

    def test_verify_malformed_token(self, http_client: httpx.Client):
        """A malformed token should return 401."""
        headers = {"Authorization": "Bearer not-a-jwt"}
        resp = http_client.get(f"{AUTH_URL}/verify", headers=headers)
        assert resp.status_code == 401


@pytest.mark.auth
class TestTokenRefresh:
    """POST /auth/refresh — token rotation workflow."""

    def test_refresh_valid_token(self, http_client: httpx.Client, auth_token: str):
        """A valid refresh should return a new token pair."""
        # First login to get a refresh token
        if not AUTH_PASS:
            pytest.skip("COBALTO_E2E_PASS not set")

        login_resp = http_client.post(
            f"{AUTH_URL}/login",
            json={"username": AUTH_USER, "password": AUTH_PASS},
        )
        assert login_resp.status_code == 200
        refresh_token = login_resp.json()["refresh_token"]

        # Refresh
        resp = http_client.post(
            f"{AUTH_URL}/refresh",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

        # Tokens should be rotated (different from original)
        assert data["access_token"] != login_resp.json()["access_token"]
        assert data["refresh_token"] != refresh_token

    def test_old_refresh_revoked_after_use(self, http_client: httpx.Client):
        """A used refresh token should be revoked (rotation security)."""
        if not AUTH_PASS:
            pytest.skip("COBALTO_E2E_PASS not set")

        login_resp = http_client.post(
            f"{AUTH_URL}/login",
            json={"username": AUTH_USER, "password": AUTH_PASS},
        )
        assert login_resp.status_code == 200
        orig_refresh = login_resp.json()["refresh_token"]

        # First use — succeeds
        resp1 = http_client.post(
            f"{AUTH_URL}/refresh",
            json={"refresh_token": orig_refresh},
        )
        assert resp1.status_code == 200

        # Second use with same token — must fail (rotated)
        resp2 = http_client.post(
            f"{AUTH_URL}/refresh",
            json={"refresh_token": orig_refresh},
        )
        assert resp2.status_code == 401, "Old refresh token was not revoked"

    def test_refresh_with_invalid_token(self, http_client: httpx.Client):
        """An invalid refresh token should return 401."""
        resp = http_client.post(
            f"{AUTH_URL}/refresh",
            json={"refresh_token": "totally-invalid-token"},
        )
        assert resp.status_code == 401


@pytest.mark.auth
class TestLogout:
    """POST /auth/logout — session termination."""

    def test_logout_revokes_refresh(self, http_client: httpx.Client):
        """After logout, the refresh token should be revoked."""
        if not AUTH_PASS:
            pytest.skip("COBALTO_E2E_PASS not set")

        # Login
        login_resp = http_client.post(
            f"{AUTH_URL}/login",
            json={"username": AUTH_USER, "password": AUTH_PASS},
        )
        assert login_resp.status_code == 200
        refresh_token = login_resp.json()["refresh_token"]

        # Logout
        resp = http_client.post(
            f"{AUTH_URL}/logout",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 204

        # Refresh should now fail
        refresh_resp = http_client.post(
            f"{AUTH_URL}/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_resp.status_code == 401

    def test_logout_no_token(self, http_client: httpx.Client):
        """Logout with a non-existent token should still succeed."""
        resp = http_client.post(
            f"{AUTH_URL}/logout",
            json={"refresh_token": "nonexistent-token"},
        )
        # Should not error — best-effort revocation
        assert resp.status_code in (204, 401)
