"""Tests for MCP Connection Pool with circuit breaker."""

import pytest
import httpx
from cobalto.mcp.transport.pool import (
    CircuitBreaker,
    MCPConnectionPool,
    execute_request,
    get_pool,
    close_pool,
)


class TestCircuitBreaker:
    """Tests for CircuitBreaker."""

    @pytest.mark.asyncio
    async def test_initial_state_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitBreaker.CLOSED

    @pytest.mark.asyncio
    async def test_allow_request_when_closed(self):
        cb = CircuitBreaker()
        allowed = await cb.allow_request()
        assert allowed is True

    @pytest.mark.asyncio
    async def test_record_failure_opens_on_threshold(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
        await cb.record_failure()
        await cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN

    @pytest.mark.asyncio
    async def test_deny_request_when_open(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=60)
        await cb.record_failure()
        allowed = await cb.allow_request()
        assert allowed is False

    @pytest.mark.asyncio
    async def test_success_resets_failures(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
        await cb.record_failure()
        await cb.record_success()
        await cb.record_failure()
        assert cb.state == CircuitBreaker.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_after_cooldown(self):
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.01)
        await cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN
        import asyncio
        await asyncio.sleep(0.02)
        allowed = await cb.allow_request()
        assert allowed is True
        assert cb.state == CircuitBreaker.HALF_OPEN

    @pytest.mark.asyncio
    async def test_to_dict(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=30)
        info = cb.to_dict()
        assert info["state"] == "closed"
        assert info["failures"] == 0
        assert info["failure_threshold"] == 3
        assert info["cooldown_seconds"] == 30


class TestPool:
    """Tests for MCPConnectionPool."""

    @pytest.mark.asyncio
    async def test_get_client_creates_new(self):
        pool = MCPConnectionPool()
        client = await pool.get_client("test", "http://localhost:9999")
        assert client is not None
        assert isinstance(client, httpx.AsyncClient)
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_get_client_reuses(self):
        pool = MCPConnectionPool()
        client1 = await pool.get_client("test", "http://localhost:9999")
        client2 = await pool.get_client("test", "http://localhost:9999")
        assert client1 is client2
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_get_pool_info(self):
        pool = MCPConnectionPool()
        await pool.get_client("test", "http://localhost:9999")
        info = await pool.get_pool_info()
        assert info["total_pools"] == 1
        assert "test" in info["pools"]
        assert info["pools"]["test"]["base_url"] == "http://localhost:9999"
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_record_success_and_failure(self):
        pool = MCPConnectionPool()
        await pool.get_client("test", "http://localhost:9999")
        await pool.record_success("test")
        await pool.record_failure("test")
        info = await pool.get_pool_info()
        assert info["pools"]["test"]["requests_count"] == 1
        assert info["pools"]["test"]["failures_count"] == 1
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_reset_breaker(self):
        pool = MCPConnectionPool(default_failure_threshold=2)
        await pool.get_client("test", "http://localhost:9999")
        await pool.record_failure("test")
        await pool.record_failure("test")
        info = await pool.get_pool_info()
        assert info["pools"]["test"]["breaker"]["state"] == "open"
        await pool.reset_breaker("test")
        info = await pool.get_pool_info()
        assert info["pools"]["test"]["breaker"]["state"] == "closed"
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_evict_client(self):
        pool = MCPConnectionPool()
        await pool.get_client("test", "http://localhost:9999")
        await pool.evict("test")
        info = await pool.get_pool_info()
        assert info["total_pools"] == 0

    @pytest.mark.asyncio
    async def test_close_all(self):
        pool = MCPConnectionPool()
        await pool.get_client("test1", "http://localhost:9999")
        await pool.get_client("test2", "http://localhost:9999")
        await pool.close_all()
        assert pool._entries == {}

    @pytest.mark.asyncio
    async def test_circuit_breaker_raises_on_open(self):
        pool = MCPConnectionPool(default_failure_threshold=1, default_cooldown_seconds=60)
        await pool.get_client("test", "http://localhost:9999")
        await pool.record_failure("test")
        with pytest.raises(httpx.HTTPError, match="Circuit breaker open"):
            await pool.get_client("test", "http://localhost:9999")
        await pool.close_all()


class TestGlobalPool:
    """Tests for global pool singleton."""

    @pytest.mark.asyncio
    async def test_get_pool_returns_singleton(self):
        pool1 = await get_pool()
        pool2 = await get_pool()
        assert pool1 is pool2
        await close_pool()

    @pytest.mark.asyncio
    async def test_close_pool_clears(self):
        pool = await get_pool()
        await pool.get_client("test", "http://localhost:9999")
        await close_pool()
        new_pool = await get_pool()
        assert id(pool) != id(new_pool)
        await close_pool()

    @pytest.mark.asyncio
    async def test_execute_request_fails_on_bad_url(self):
        with pytest.raises(httpx.HTTPError):
            await execute_request(
                name="bad_url_test",
                base_url="http://localhost:1",
                method="GET",
                path="/",
                timeout=1.0,
            )
        await close_pool()
