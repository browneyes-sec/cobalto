"""
MCP Connection Pool

Manages pooled HTTP clients with circuit breaker support.
Replaces per-call httpx.AsyncClient() with shared, reusable sessions.
"""

from typing import Any, Dict, Optional, Callable
from dataclasses import dataclass, field
import time
import asyncio
import httpx
import structlog

logger = structlog.get_logger(__name__)


class CircuitBreaker:
    """Circuit breaker for a single endpoint.

    Tracks consecutive failures and enters open state when threshold is exceeded.
    After cooldown, transitions to half-open for one probe request.
    """

    OPEN = "open"
    HALF_OPEN = "half_open"
    CLOSED = "closed"

    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._failures = 0
        self._state = self.CLOSED
        self._last_failure_time = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            if self._state == self.HALF_OPEN:
                self._state = self.CLOSED
                logger.info("circuit_breaker_closed")

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            self._last_failure_time = time.monotonic()
            if self._failures >= self.failure_threshold:
                self._state = self.OPEN
                logger.warning("circuit_breaker_opened", failures=self._failures)

    async def allow_request(self) -> bool:
        async with self._lock:
            if self._state == self.CLOSED:
                return True
            if self._state == self.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.cooldown_seconds:
                    self._state = self.HALF_OPEN
                    logger.info("circuit_breaker_half_open")
                    return True
                return False
            return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self._state,
            "failures": self._failures,
            "failure_threshold": self.failure_threshold,
            "cooldown_seconds": self.cooldown_seconds,
        }


@dataclass
class PoolEntry:
    """A pooled client entry for a single domain/endpoint."""
    client: httpx.AsyncClient
    breaker: CircuitBreaker
    base_url: str
    name: str
    created_at: float = field(default_factory=time.monotonic)
    requests_count: int = 0
    failures_count: int = 0


class MCPConnectionPool:
    """Manages pooled HTTP connections per domain.

    Provides shared httpx.AsyncClient instances with:
    - Connection reuse and limit management
    - Per-endpoint circuit breaker
    - Health and metrics reporting
    """

    def __init__(
        self,
        default_max_connections: int = 10,
        default_max_keepalive: int = 5,
        default_timeout: float = 30.0,
        default_failure_threshold: int = 3,
        default_cooldown_seconds: float = 30.0,
    ):
        self._default_max_connections = default_max_connections
        self._default_max_keepalive = default_max_keepalive
        self._default_timeout = default_timeout
        self._default_failure_threshold = default_failure_threshold
        self._default_cooldown_seconds = default_cooldown_seconds
        self._entries: Dict[str, PoolEntry] = {}
        self._lock = asyncio.Lock()

    async def get_client(
        self,
        name: str,
        base_url: str,
        *,
        timeout: Optional[float] = None,
        verify: bool = True,
        auth: Optional[tuple[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        limits: Optional[httpx.Limits] = None,
    ) -> httpx.AsyncClient:
        """Get or create a pooled HTTP client for the given endpoint name.

        Args:
            name: Unique key for this endpoint (e.g. "wazuh", "opencti")
            base_url: Base URL for the endpoint
            timeout: Request timeout in seconds
            verify: SSL verification
            auth: Basic auth tuple
            headers: Default headers to include on every request
            limits: httpx connection limits

        Returns:
            httpx.AsyncClient ready to use

        Raises:
            httpx.HTTPError: If circuit breaker is open
        """
        async with self._lock:
            entry = self._entries.get(name)

            if entry is None:
                client = self._build_client(
                    base_url=base_url,
                    timeout=timeout or self._default_timeout,
                    verify=verify,
                    auth=auth,
                    headers=headers,
                    limits=limits,
                )
                entry = PoolEntry(
                    client=client,
                    breaker=CircuitBreaker(
                        failure_threshold=self._default_failure_threshold,
                        cooldown_seconds=self._default_cooldown_seconds,
                    ),
                    base_url=base_url,
                    name=name,
                )
                self._entries[name] = entry
                logger.info("pool_client_created", name=name, base_url=base_url)

            allowed = await entry.breaker.allow_request()
            if not allowed:
                raise httpx.HTTPError(
                    f"Circuit breaker open for '{name}', "
                    f"retry after {entry.breaker.cooldown_seconds}s cooldown"
                )

            return entry.client

    def _build_client(
        self,
        base_url: str,
        timeout: float,
        verify: bool,
        auth: Optional[tuple[str, str]],
        headers: Optional[Dict[str, str]],
        limits: Optional[httpx.Limits],
    ) -> httpx.AsyncClient:
        """Build a configured AsyncClient."""
        if limits is None:
            limits = httpx.Limits(
                max_connections=self._default_max_connections,
                max_keepalive_connections=self._default_max_keepalive,
            )

        client_headers: Dict[str, str] = {}
        if headers:
            client_headers.update(headers)

        return httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(timeout),
            verify=verify,
            auth=auth,
            headers=client_headers or None,
            limits=limits,
        )

    async def record_success(self, name: str) -> None:
        """Record a successful request for the given endpoint."""
        async with self._lock:
            entry = self._entries.get(name)
            if entry:
                await entry.breaker.record_success()
                entry.requests_count += 1

    async def record_failure(self, name: str) -> None:
        """Record a failed request for the given endpoint."""
        async with self._lock:
            entry = self._entries.get(name)
            if entry:
                await entry.breaker.record_failure()
                entry.failures_count += 1

    async def reset_breaker(self, name: str) -> None:
        """Reset the circuit breaker for an endpoint."""
        async with self._lock:
            entry = self._entries.get(name)
            if entry:
                entry.breaker._failures = 0
                entry.breaker._state = CircuitBreaker.CLOSED

    async def evict(self, name: str) -> None:
        """Remove and close a client from the pool."""
        async with self._lock:
            entry = self._entries.pop(name, None)
            if entry:
                await entry.client.aclose()
                logger.info("pool_client_evicted", name=name)

    async def get_pool_info(self) -> Dict[str, Any]:
        """Get health/metrics for all pooled connections."""
        info: Dict[str, Any] = {"pools": {}}
        async with self._lock:
            for name, entry in self._entries.items():
                info["pools"][name] = {
                    "base_url": entry.base_url,
                    "breaker": entry.breaker.to_dict(),
                    "requests_count": entry.requests_count,
                    "failures_count": entry.failures_count,
                    "created_at": entry.created_at,
                    "age_seconds": time.monotonic() - entry.created_at,
                }
            info["total_pools"] = len(self._entries)
        return info

    async def close_all(self) -> None:
        """Close all pooled clients."""
        async with self._lock:
            for name, entry in self._entries.items():
                await entry.client.aclose()
            self._entries.clear()
            logger.info("pool_all_clients_closed")


# Global singleton
_pool: Optional[MCPConnectionPool] = None
_pool_lock = asyncio.Lock()


async def get_pool() -> MCPConnectionPool:
    """Get or create the global connection pool."""
    global _pool
    if _pool is None:
        async with _pool_lock:
            if _pool is None:
                _pool = MCPConnectionPool()
    return _pool


async def close_pool() -> None:
    """Close the global connection pool."""
    global _pool
    if _pool:
        await _pool.close_all()
        _pool = None


async def execute_request(
    name: str,
    base_url: str,
    method: str,
    path: str,
    *,
    json: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[tuple[str, str]] = None,
    verify: bool = True,
    timeout: float = 30.0,
) -> Any:
    """Execute an HTTP request through the connection pool.

    Handles client lifecycle, circuit breaker, and metrics recording.

    Args:
        name: Pool endpoint key (e.g. "wazuh", "opencti")
        base_url: Base URL for the endpoint
        method: HTTP method (get, post, put, delete, patch)
        path: URL path relative to base_url
        json: JSON body for POST/PUT/PATCH
        params: Query parameters
        headers: Additional request headers
        auth: Basic auth credentials
        verify: SSL verification
        timeout: Request timeout in seconds

    Returns:
        Parsed JSON response body

    Raises:
        httpx.HTTPError: On request failure or open circuit breaker
    """
    pool = await get_pool()
    client = await pool.get_client(
        name=name,
        base_url=base_url,
        timeout=timeout,
        verify=verify,
        auth=auth,
        headers=headers,
    )

    try:
        response = await client.request(
            method=method,
            url=path,
            json=json,
            params=params,
        )
        response.raise_for_status()
        await pool.record_success(name)
        return response.json()

    except httpx.HTTPError as e:
        await pool.record_failure(name)
        logger.error(
            "pool_request_failed",
            name=name,
            method=method,
            path=path,
            error=str(e),
        )
        raise
