"""
Cobalto Console Auth Service

Lightweight JWT authentication service for the Cobalt SOC console.
Handles login, token refresh, and token verification (used by nginx auth_request).

Architecture:
  ┌──────────┐    auth_request     ┌──────────────┐
  │  nginx   │ ──────────────────▶ │ console-auth │
  │ (proxy)  │ ◀────────────────── │  (:8001)     │
  │          │    X-Auth-User      └──────────────┘
  │          │       header
  │          │ ──────────────────▶ │  backend     │
  └──────────┘                     └──────────────┘

Security:
  - Access tokens: short-lived (15 min), HMAC-SHA256 signed
  - Refresh tokens: long-lived (7 days), stored as SHA-256 hash
  - Passwords: bcrypt hashed, never stored in plaintext
  - Rate limiting: 5 login attempts per IP per minute
  - Audit logging: all auth events logged to stderr as JSON
"""

import os
import re
import time
import uuid
import json
import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

import bcrypt
import jwt as pyjwt
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# ── Configuration ────────────────────────────────────────────────────

class AuthSettings(BaseSettings):
    """Console auth configuration — sourced from env/Vault."""
    JWT_SECRET: str = Field(
        default="change-me-in-production",
        description="HMAC key for signing JWT tokens",
    )
    JWT_ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)
    RATE_LIMIT_PER_MINUTE: int = Field(default=5)
    LOG_LEVEL: str = Field(default="INFO")

    # Comma-separated: "username:bcrypt_hash,username2:bcrypt_hash2"
    USERS: str = Field(
        default="",
        description="User credentials in Vault or env",
    )

    model_config = {"env_prefix": "CONSOLE_AUTH_", "case_sensitive": True}


settings = AuthSettings()


# ── Logger Setup ─────────────────────────────────────────────────────

def setup_logger() -> logging.Logger:
    """Configure structured JSON logger for auth events."""
    logger = logging.getLogger("cobalto.console-auth")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '{"timestamp":"%(asctime)s","level":"%(levelname)s",'
            '"logger":"%(name)s","message":"%(message)s"}'
        ))
        logger.addHandler(handler)
    logger.propagate = False
    return logger


logger = setup_logger()


# ── User Store ───────────────────────────────────────────────────────

class UserEntry(BaseModel):
    """A registered user with bcrypt-hashed password."""
    username: str
    password_hash: str
    role: str = "analyst"
    display_name: str = ""


def load_users(users_str: str) -> dict[str, UserEntry]:
    """
    Parse the USERS config string into a dict of username → UserEntry.

    Format: "username:bcrypt_hash[:role:display_name],..."
    Example: "admin:$2b$12$...:admin:Admin User,analyst:$2b$12$...:analyst:Jane Doe"
    """
    users: dict[str, UserEntry] = {}
    if not users_str:
        return users

    for entry in users_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":", 3)
        if len(parts) < 2:
            logger.warning("Skipping malformed user entry")
            continue
        username = parts[0]
        password_hash = parts[1]
        role = parts[2] if len(parts) > 2 else "analyst"
        display_name = parts[3] if len(parts) > 3 else username
        users[username] = UserEntry(
            username=username,
            password_hash=password_hash,
            role=role,
            display_name=display_name,
        )
    return users


# Global user store — loaded at startup
_users: dict[str, UserEntry] = {}


# ── Token Management ─────────────────────────────────────────────────

# In-memory store of valid refresh token hashes (for single-instance dev)
# In production, this would be Redis/Vault with TTL
_refresh_token_hashes: set[str] = set()


def create_access_token(username: str, role: str) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),
        "type": "access",
    }
    return pyjwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(username: str) -> str:
    """Create a long-lived refresh token and store its hash."""
    now = datetime.now(timezone.utc)
    token_id = str(uuid.uuid4())
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "jti": token_id,
        "type": "refresh",
    }
    token = pyjwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    # Store SHA-256 hash of refresh token for revocation
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    _refresh_token_hashes.add(token_hash)

    return token


def verify_access_token(token: str) -> dict | None:
    """Verify and decode an access token. Returns payload or None."""
    try:
        payload = pyjwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "access":
            return None
        return payload
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None


def verify_refresh_token(token: str) -> dict | None:
    """Verify a refresh token and check its hash against stored set."""
    try:
        payload = pyjwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "refresh":
            return None

        # Verify token hash is in our store (not revoked)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash not in _refresh_token_hashes:
            return None

        return payload
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None


def revoke_refresh_token(token: str) -> bool:
    """Revoke a refresh token by removing its hash."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if token_hash in _refresh_token_hashes:
        _refresh_token_hashes.discard(token_hash)
        return True
    return False


# ── Rate Limiter (in-memory, single-instance) ───────────────────────

class LoginRateLimiter:
    """Simple sliding-window rate limiter for login attempts."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self._max = max_attempts
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        """Check if key (IP/username) is allowed to attempt login."""
        now = time.monotonic()
        window_start = now - self._window

        # Purge old entries
        if key in self._attempts:
            self._attempts[key] = [t for t in self._attempts[key] if t > window_start]

        attempts = self._attempts.get(key, [])
        return len(attempts) < self._max

    def record_attempt(self, key: str) -> None:
        """Record a login attempt for a key."""
        if key not in self._attempts:
            self._attempts[key] = []
        self._attempts[key].append(time.monotonic())

    def remaining(self, key: str) -> int:
        """Get remaining attempts for a key."""
        now = time.monotonic()
        window_start = now - self._window
        if key in self._attempts:
            self._attempts[key] = [t for t in self._attempts[key] if t > window_start]
            return max(0, self._max - len(self._attempts[key]))
        return self._max


rate_limiter = LoginRateLimiter(max_attempts=settings.RATE_LIMIT_PER_MINUTE)


# ── FastAPI App ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load users from config on startup."""
    global _users
    _users = load_users(settings.USERS)
    logger.info(
        "Console auth started",
        extra={"users_loaded": len(_users), "rate_limit": settings.RATE_LIMIT_PER_MINUTE},
    )
    yield


app = FastAPI(
    title="Cobalto Console Auth",
    version="1.0.0",
    description="JWT authentication service for Cobalt SOC console",
    lifespan=lifespan,
)


# ── Models ───────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class VerifyResponse(BaseModel):
    valid: bool
    username: str = ""
    role: str = ""
    display_name: str = ""


class ErrorResponse(BaseModel):
    error: str
    message: str


# ── Endpoints ────────────────────────────────────────────────────────

@app.post(
    "/auth/login",
    response_model=TokenResponse,
    responses={401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    summary="Authenticate user credentials",
    description="Verify username/password and return JWT access + refresh tokens.",
)
async def login(body: LoginRequest, request: Request):
    """
    Authenticate a user and issue JWT tokens.

    Rate-limited per IP address (5 attempts/minute by default).
    Returns 401 on invalid credentials, 429 on rate limit exceeded.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{body.username}"

    # Rate limiting
    if not rate_limiter.is_allowed(rate_key):
        remaining = rate_limiter.remaining(rate_key)
        logger.warning(
            "Rate limit exceeded for login",
            extra={"username": body.username, "ip": client_ip},
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "message": f"Too many login attempts. Try again in 60 seconds.",
                "retry_after_seconds": 60,
            },
        )

    # Validate credentials
    user = _users.get(body.username)
    if not user:
        rate_limiter.record_attempt(rate_key)
        logger.info(
            "Login failed: unknown user",
            extra={"username": body.username, "ip": client_ip},
        )
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_credentials",
                "message": "Invalid username or password",
            },
        )

    # Verify password
    try:
        password_bytes = body.password.encode("utf-8")
        hash_bytes = user.password_hash.encode("utf-8")
        if not bcrypt.checkpw(password_bytes, hash_bytes):
            rate_limiter.record_attempt(rate_key)
            logger.info(
                "Login failed: wrong password",
                extra={"username": body.username, "ip": client_ip},
            )
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_credentials",
                    "message": "Invalid username or password",
                },
            )
    except (ValueError, AttributeError) as e:
        # Invalid bcrypt hash format
        rate_limiter.record_attempt(rate_key)
        logger.error("Password verification error", extra={"error": str(e)})
        raise HTTPException(
            status_code=500,
            detail={"error": "internal_error", "message": "Authentication error"},
        )

    # Issue tokens
    access_token = create_access_token(user.username, user.role)
    refresh_token = create_refresh_token(user.username)

    logger.info(
        "Login successful",
        extra={"username": user.username, "role": user.role, "ip": client_ip},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "username": user.username,
            "role": user.role,
            "display_name": user.display_name,
        },
    )


@app.post(
    "/auth/refresh",
    response_model=TokenResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Refresh an access token",
    description="Exchange a valid refresh token for a new access + refresh token pair.",
)
async def refresh(body: RefreshRequest):
    """
    Refresh JWT tokens.

    Validates the refresh token, revokes it, and issues a new pair.
    This provides rotation: each refresh invalidates the previous token.
    """
    payload = verify_refresh_token(body.refresh_token)
    if not payload:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_token",
                "message": "Refresh token is invalid or expired",
            },
        )

    username = payload.get("sub", "")
    user = _users.get(username)
    if not user:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_token",
                "message": "User no longer exists",
            },
        )

    # Revoke old refresh token (rotation)
    revoke_refresh_token(body.refresh_token)

    # Issue new tokens
    access_token = create_access_token(user.username, user.role)
    new_refresh_token = create_refresh_token(user.username)

    logger.info("Tokens refreshed", extra={"username": username})

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "username": user.username,
            "role": user.role,
            "display_name": user.display_name,
        },
    )


@app.get(
    "/auth/verify",
    response_model=VerifyResponse,
    summary="Verify an access token (for nginx auth_request)",
    description="Validates the Authorization Bearer token. Used by nginx auth_request directive.",
)
async def verify(request: Request):
    """
    Verify a JWT access token.

    This endpoint is called by nginx's auth_request directive.
    Returns 200 with user info on success, 401 on invalid/expired token.

    Expected header: Authorization: Bearer <token>
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"valid": False, "error": "missing_token"},
        )

    token = auth_header[7:]  # Strip "Bearer "
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=401,
            detail={"valid": False, "error": "invalid_or_expired_token"},
        )

    username = payload.get("sub", "")
    user = _users.get(username)

    return VerifyResponse(
        valid=True,
        username=username,
        role=payload.get("role", ""),
        display_name=user.display_name if user else username,
    )


@app.post(
    "/auth/logout",
    status_code=204,
    summary="Logout and revoke refresh token",
    description="Revoke a refresh token so it can no longer be used.",
)
async def logout(body: RefreshRequest):
    """Revoke the provided refresh token."""
    revoked = revoke_refresh_token(body.refresh_token)
    if revoked:
        logger.info("Token revoked on logout")
    return Response(status_code=204)


@app.get("/health")
async def health():
    """Liveness probe."""
    return {"status": "healthy", "service": "console-auth"}


@app.get("/ready")
async def ready():
    """Readiness probe."""
    return {
        "status": "ready",
        "service": "console-auth",
        "users_loaded": len(_users),
    }


# ── Entry Point ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        log_level=settings.LOG_LEVEL.lower(),
    )
