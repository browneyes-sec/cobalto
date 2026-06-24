"""
MCP Authentication Middleware - JWT and API Key authentication.
"""

from typing import Any, Callable, Dict, Optional
from datetime import datetime, timedelta
import jwt
import hashlib
import secrets

from cobalto.mcp.protocol import JSONRPCRequest, JSONRPCResponse, JSONRPCError, JSONRPCErrorCode


class MCPAuthMiddleware:
    """Authentication middleware for MCP server."""

    def __init__(
        self,
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
        api_keys: Optional[Dict[str, str]] = None,
        require_auth: bool = True,
    ):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.api_keys = api_keys or {}
        self.require_auth = require_auth
        self._token_cache: Dict[str, datetime] = {}

    def validate_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and return payload."""
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm],
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def validate_api_key(self, api_key: str) -> Optional[str]:
        """Validate API key and return associated user/tenant."""
        return self.api_keys.get(api_key)

    def create_jwt(
        self,
        subject: str,
        expires_delta: Optional[timedelta] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a JWT token."""
        now = datetime.utcnow()
        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(hours=1)

        payload = {
            "sub": subject,
            "iat": now,
            "exp": expire,
            "type": "access",
        }
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def extract_auth(self, request: JSONRPCRequest) -> Optional[Dict[str, Any]]:
        """
        Extract authentication from request.

        Checks:
        1. params.auth.token (JWT)
        2. params.auth.api_key (API Key)
        """
        if not self.require_auth:
            return {"authenticated": True, "method": "none"}

        params = request.params or {}
        auth = params.get("auth", {})

        # Check JWT
        if "token" in auth:
            payload = self.validate_jwt(auth["token"])
            if payload:
                return {
                    "authenticated": True,
                    "method": "jwt",
                    "subject": payload.get("sub"),
                    "claims": payload,
                }

        # Check API Key
        if "api_key" in auth:
            user = self.validate_api_key(auth["api_key"])
            if user:
                return {
                    "authenticated": True,
                    "method": "api_key",
                    "subject": user,
                }

        # No auth provided
        return None

    async def __call__(
        self,
        request: JSONRPCRequest,
        handler: Callable,
    ) -> JSONRPCResponse:
        """Process request with authentication."""
        auth_result = self.extract_auth(request)

        if not auth_result and self.require_auth:
            return JSONRPCResponse(
                id=request.id,
                error=JSONRPCError(
                    code=JSONRPCErrorCode.INTERNAL_ERROR,
                    message="Authentication required",
                ),
            )

        # Add auth context to request
        if auth_result:
            if request.params is None:
                request.params = {}
            request.params["_auth"] = auth_result

        return await handler(request)


class APIKeyManager:
    """Manage API keys for MCP authentication."""

    def __init__(self):
        self._keys: Dict[str, Dict[str, Any]] = {}

    def generate_key(
        self,
        name: str,
        tenant_id: str,
        permissions: Optional[list] = None,
        expires_days: Optional[int] = None,
    ) -> str:
        """Generate a new API key."""
        api_key = f"cobalto_{secrets.token_hex(32)}"

        self._keys[api_key] = {
            "name": name,
            "tenant_id": tenant_id,
            "permissions": permissions or ["read"],
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (
                (datetime.utcnow() + timedelta(days=expires_days)).isoformat()
                if expires_days
                else None
            ),
        }

        return api_key

    def validate_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate an API key."""
        key_info = self._keys.get(api_key)
        if not key_info:
            return None

        # Check expiration
        if key_info.get("expires_at"):
            expires = datetime.fromisoformat(key_info["expires_at"])
            if datetime.utcnow() > expires:
                del self._keys[api_key]
                return None

        return key_info

    def revoke_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        if api_key in self._keys:
            del self._keys[api_key]
            return True
        return False

    def list_keys(self) -> Dict[str, Dict[str, Any]]:
        """List all API keys (without the actual keys for security)."""
        return {
            key[:10] + "...": {
                "name": info["name"],
                "tenant_id": info["tenant_id"],
                "created_at": info["created_at"],
            }
            for key, info in self._keys.items()
        }
