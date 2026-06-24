"""
MCP Rate Limiting Middleware - Token bucket rate limiting.
"""

import time
import asyncio
from typing import Any, Callable, Dict, Optional
from collections import defaultdict

from cobalto.mcp.protocol import JSONRPCRequest, JSONRPCResponse, JSONRPCError, JSONRPCErrorCode


class TokenBucket:
    """Token bucket for rate limiting."""

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens per second refill rate
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens."""
        self._refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        refill_amount = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + refill_amount)
        self.last_refill = now

    @property
    def available_tokens(self) -> int:
        """Get available tokens."""
        self._refill()
        return int(self.tokens)


class MCPRateLimitMiddleware:
    """Rate limiting middleware for MCP server."""

    def __init__(
        self,
        requests_per_minute: int = 100,
        requests_per_hour: int = 1000,
        burst_size: int = 20,
        per_client: bool = True,
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_size = burst_size
        self.per_client = per_client

        # Buckets per client
        self._minute_buckets: Dict[str, TokenBucket] = {}
        self._hour_buckets: Dict[str, TokenBucket] = {}

        # Global buckets
        self._global_minute = TokenBucket(requests_per_minute, requests_per_minute / 60)
        self._global_hour = TokenBucket(requests_per_hour, requests_per_hour / 3600)

    def _get_client_id(self, request: JSONRPCRequest) -> str:
        """Get client identifier from request."""
        params = request.params or {}
        auth = params.get("_auth", {})
        return auth.get("subject", "anonymous")

    def _get_or_create_buckets(self, client_id: str) -> tuple:
        """Get or create rate limit buckets for client."""
        if client_id not in self._minute_buckets:
            self._minute_buckets[client_id] = TokenBucket(
                self.burst_size,
                self.requests_per_minute / 60,
            )
            self._hour_buckets[client_id] = TokenBucket(
                self.requests_per_hour,
                self.requests_per_hour / 3600,
            )

        return (
            self._minute_buckets[client_id],
            self._hour_buckets[client_id],
        )

    def check_rate_limit(self, client_id: str) -> tuple:
        """
        Check if request is within rate limits.

        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        minute_bucket, hour_bucket = self._get_or_create_buckets(client_id)

        # Check minute limit
        if not minute_bucket.consume():
            retry_after = 60 - (time.time() - minute_bucket.last_refill)
            return False, max(1, int(retry_after))

        # Check hour limit
        if not hour_bucket.consume():
            retry_after = 3600 - (time.time() - hour_bucket.last_refill)
            return False, max(1, int(retry_after))

        # Check global limits
        if not self._global_minute.consume():
            return False, 60

        if not self._global_hour.consume():
            return False, 3600

        return True, 0

    async def __call__(
        self,
        request: JSONRPCRequest,
        handler: Callable,
    ) -> JSONRPCResponse:
        """Process request with rate limiting."""
        client_id = self._get_client_id(request) if self.per_client else "global"

        allowed, retry_after = self.check_rate_limit(client_id)

        if not allowed:
            return JSONRPCResponse(
                id=request.id,
                error=JSONRPCError(
                    code=-32000,
                    message="Rate limit exceeded",
                    data={"retry_after_seconds": retry_after},
                ),
            )

        return await handler(request)

    def get_rate_limit_headers(self, client_id: str) -> Dict[str, str]:
        """Get rate limit headers for response."""
        minute_bucket, hour_bucket = self._get_or_create_buckets(client_id)

        return {
            "X-RateLimit-Limit-Minute": str(self.requests_per_minute),
            "X-RateLimit-Remaining-Minute": str(minute_bucket.available_tokens),
            "X-RateLimit-Limit-Hour": str(self.requests_per_hour),
            "X-RateLimit-Remaining-Hour": str(hour_bucket.available_tokens),
        }

    def reset(self, client_id: Optional[str] = None) -> None:
        """Reset rate limits for a client or all clients."""
        if client_id:
            self._minute_buckets.pop(client_id, None)
            self._hour_buckets.pop(client_id, None)
        else:
            self._minute_buckets.clear()
            self._hour_buckets.clear()
