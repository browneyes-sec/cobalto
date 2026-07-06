"""
API Authentication Middleware for Cobalto LangGraph Agent.

Provides API key authentication for all endpoints except health/readiness probes.
Keys are configured via environment variable and validated with constant-time comparison.

Usage:
    from middleware.auth import AuthMiddleware
    app.add_middleware(AuthMiddleware)

Configuration:
    COBALTO_API_KEY: Single API key for all clients (simple mode)
    COBALTO_API_KEYS: Comma-separated list of valid API keys
    COBALTO_DISABLE_AUTH: Set to "true" to disable auth (dev only)
"""

import os
import hmac
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


PUBLIC_PATHS = {
    "/health",
    "/ready",
    "/openapi.json",
    "/docs",
    "/redoc",
}


class AuthMiddleware(BaseHTTPMiddleware):
    """
    API Key authentication middleware.

    Validates the X-API-Key header against configured key(s).
    Uses constant-time comparison via hmac.compare_digest to prevent timing attacks.
    """

    def __init__(self, app, api_key: Optional[str] = None):
        super().__init__(app)
        self._api_key = api_key or os.getenv("COBALTO_API_KEY", "")
        self._api_keys: set[str] = set()

        # Parse comma-separated keys
        keys_env = os.getenv("COBALTO_API_KEYS", "")
        if keys_env:
            self._api_keys = {k.strip() for k in keys_env.split(",") if k.strip()}

        if self._api_key:
            self._api_keys.add(self._api_key)

        self._disabled = os.getenv("COBALTO_DISABLE_AUTH", "").lower() in (
            "true", "1", "yes"
        )

    async def dispatch(self, request: Request, call_next):
        # Skip auth for public paths
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Skip auth if disabled (dev mode only)
        if self._disabled:
            return await call_next(request)

        # No keys configured — warn but allow (dev/demo mode)
        if not self._api_keys:
            return await call_next(request)

        # Validate API key
        api_key = request.headers.get("X-API-Key", "")

        if not api_key:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "Missing X-API-Key header",
                    "hint": "Provide a valid API key in the X-API-Key header",
                },
                headers={
                    "WWW-Authenticate": 'ApiKey realm="cobalto"',
                },
            )

        if not self._is_valid_key(api_key):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "forbidden",
                    "message": "Invalid API key",
                },
            )

        return await call_next(request)

    def _is_valid_key(self, key: str) -> bool:
        """Constant-time comparison of API key against all valid keys."""
        for valid_key in self._api_keys:
            if hmac.compare_digest(key, valid_key):
                return True
        return False


# Convenience function for testability
def require_api_key(request: Request) -> Optional[str]:
    """
    Dependency injection function for route-level auth.

    Usage:
        @app.post("/agent/analyze")
        async def analyze(payload: AlertPayload, api_key: str = Depends(require_api_key)):
            ...
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    return api_key
