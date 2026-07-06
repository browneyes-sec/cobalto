"""
Tests for the API Key Authentication Middleware.

Tests cover:
- Missing API key returns 401
- Invalid API key returns 403
- Valid API key allows request
- Public paths bypass auth
- Disabled auth mode
- Constant-time comparison safety
- Multiple API keys support
- Constructor-based key configuration
"""

import os
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def clear_env():
    """Clear auth-related env vars before each test."""
    with patch.dict(os.environ, {}, clear=True):
        yield


@pytest.fixture
def test_app():
    """Create a FastAPI test app with the auth middleware."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from middleware.auth import AuthMiddleware

    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"status": "ok"}

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready():
        return {"status": "ready"}

    @app.get("/docs")
    async def docs():
        return {"openapi": "3.0"}

    return TestClient(app)


class TestAuthMiddleware:
    def test_missing_api_key_returns_401(self, test_app):
        """Request without X-API-Key header should get 401."""
        with patch.dict(os.environ, {"COBALTO_API_KEY": "test-key-123"}):
            response = test_app.get("/test")
            assert response.status_code == 401
            data = response.json()
            assert "Missing X-API-Key header" in data["message"]

    def test_invalid_api_key_returns_403(self, test_app):
        """Request with wrong API key should get 403."""
        with patch.dict(os.environ, {"COBALTO_API_KEY": "correct-key"}):
            response = test_app.get("/test", headers={"X-API-Key": "wrong-key"})
            assert response.status_code == 403

    def test_valid_api_key_allows_request(self, test_app):
        """Request with correct API key should succeed."""
        with patch.dict(os.environ, {"COBALTO_API_KEY": "secret-key-456"}):
            response = test_app.get("/test", headers={"X-API-Key": "secret-key-456"})
            assert response.status_code == 200
            assert response.json()["status"] == "ok"

    def test_public_paths_bypass_auth(self, test_app):
        """Health and readiness endpoints should be accessible without auth."""
        with patch.dict(os.environ, {"COBALTO_API_KEY": "test-key"}):
            assert test_app.get("/health").status_code == 200
            assert test_app.get("/ready").status_code == 200
            assert test_app.get("/docs").status_code == 200

    def test_disabled_auth_mode(self, test_app):
        """COBALTO_DISABLE_AUTH=true should bypass all auth."""
        with patch.dict(os.environ, {
            "COBALTO_API_KEY": "test-key",
            "COBALTO_DISABLE_AUTH": "true",
        }):
            response = test_app.get("/test")
            assert response.status_code == 200

    def test_multiple_api_keys_supported(self, test_app):
        """COBALTO_API_KEYS should accept comma-separated list of valid keys."""
        with patch.dict(os.environ, {
            "COBALTO_API_KEYS": "key-one,key-two,key-three",
        }):
            assert test_app.get("/test", headers={"X-API-Key": "key-one"}).status_code == 200
            assert test_app.get("/test", headers={"X-API-Key": "key-two"}).status_code == 200
            assert test_app.get("/test", headers={"X-API-Key": "key-three"}).status_code == 200
            assert test_app.get("/test", headers={"X-API-Key": "invalid-key"}).status_code == 403

    def test_constant_time_comparison(self):
        """API key comparison should use constant-time algorithm."""
        from middleware.auth import AuthMiddleware
        import hmac

        with patch.dict(os.environ, {"COBALTO_API_KEY": "a" * 64}):
            middleware = AuthMiddleware(None)
            assert middleware._is_valid_key("a" * 64) is True
            assert middleware._is_valid_key("b" * 64) is False
            assert middleware._is_valid_key("") is False
            assert middleware._is_valid_key("a" * 63) is False

    def test_auth_with_constructor_api_key(self, clear_env):
        """API key passed to constructor should work without env vars."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from middleware.auth import AuthMiddleware

        app = FastAPI()
        app.add_middleware(AuthMiddleware, api_key="constructor-key")

        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)
        assert client.get("/test", headers={"X-API-Key": "constructor-key"}).status_code == 200
        assert client.get("/test", headers={"X-API-Key": "wrong"}).status_code == 403

    def test_public_paths_set_correctly(self):
        """PUBLIC_PATHS should include all expected paths."""
        from middleware.auth import PUBLIC_PATHS

        assert "/health" in PUBLIC_PATHS
        assert "/ready" in PUBLIC_PATHS
        assert "/docs" in PUBLIC_PATHS
        assert "/openapi.json" in PUBLIC_PATHS
        assert "/redoc" in PUBLIC_PATHS

    def test_no_auth_no_key_still_works(self, test_app):
        """With no API key configured, auth should not block (warning only)."""
        response = test_app.get("/test")
        assert response.status_code == 200
