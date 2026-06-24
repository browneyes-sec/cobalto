"""
Health check framework for service readiness and liveness probes.
Provides standardized health checks for Kubernetes deployments.
"""

import asyncio
import time
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from .config import get_settings
from .logging import get_logger

logger = get_logger(__name__)


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Health status for a single component."""
    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0
    last_checked: float = field(default_factory=time.time)
    details: Optional[Dict[str, Any]] = None


@dataclass
class HealthCheck:
    """Aggregated health check result."""
    status: HealthStatus
    version: str = "0.1.0"
    uptime_seconds: float = 0.0
    timestamp: float = field(default_factory=time.time)
    components: List[ComponentHealth] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "version": self.version,
            "uptime_seconds": self.uptime_seconds,
            "timestamp": self.timestamp,
            "components": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                    "latency_ms": c.latency_ms,
                    "last_checked": c.last_checked,
                    "details": c.details,
                }
                for c in self.components
            ],
        }


class HealthChecker:
    """Health check manager for Cobalto services."""

    def __init__(self, service_name: str, version: str = "0.1.0"):
        self.service_name = service_name
        self.version = version
        self._start_time = time.time()
        self._checks: Dict[str, Any] = {}

    def register_check(self, name: str, check_fn):
        """Register a health check function."""
        self._checks[name] = check_fn

    async def check_database(self) -> ComponentHealth:
        """Check database connectivity."""
        start = time.time()
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
            settings = get_settings()
            engine = create_async_engine(settings.database_url)
            async with engine.begin() as conn:
                await conn.execute("SELECT 1")
            await engine.dispose()
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="database",
                status=HealthStatus.HEALTHY,
                message="Database connection successful",
                latency_ms=latency,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def check_redis(self) -> ComponentHealth:
        """Check Redis connectivity."""
        start = time.time()
        try:
            import redis.asyncio as redis
            settings = get_settings()
            client = redis.from_url(settings.redis_url)
            await client.ping()
            await client.close()
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="redis",
                status=HealthStatus.HEALTHY,
                message="Redis connection successful",
                latency_ms=latency,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="redis",
                status=HealthStatus.UNHEALTHY,
                message=f"Redis connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def check_opensearch(self) -> ComponentHealth:
        """Check OpenSearch connectivity."""
        start = time.time()
        try:
            import httpx
            settings = get_settings()
            async with httpx.AsyncClient() as client:
                response = await client.get(settings.opensearch_url)
                latency = (time.time() - start) * 1000
                if response.status_code == 200:
                    return ComponentHealth(
                        name="opensearch",
                        status=HealthStatus.HEALTHY,
                        message="OpenSearch connection successful",
                        latency_ms=latency,
                    )
                return ComponentHealth(
                    name="opensearch",
                    status=HealthStatus.DEGRADED,
                    message=f"OpenSearch responded with status {response.status_code}",
                    latency_ms=latency,
                )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="opensearch",
                status=HealthStatus.UNHEALTHY,
                message=f"OpenSearch connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def check_wazuh(self) -> ComponentHealth:
        """Check Wazuh connectivity."""
        start = time.time()
        try:
            import httpx
            settings = get_settings()
            async with httpx.AsyncClient(verify=settings.wazuh_verify_ssl) as client:
                response = await client.get(
                    f"{settings.wazuh_url}/",
                    auth=(settings.wazuh_username, settings.wazuh_password),
                )
                latency = (time.time() - start) * 1000
                if response.status_code == 200:
                    return ComponentHealth(
                        name="wazuh",
                        status=HealthStatus.HEALTHY,
                        message="Wazuh connection successful",
                        latency_ms=latency,
                    )
                return ComponentHealth(
                    name="wazuh",
                    status=HealthStatus.DEGRADED,
                    message=f"Wazuh responded with status {response.status_code}",
                    latency_ms=latency,
                )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="wazuh",
                status=HealthStatus.UNHEALTHY,
                message=f"Wazuh connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def check_opencti(self) -> ComponentHealth:
        """Check OpenCTI connectivity."""
        start = time.time()
        try:
            import httpx
            settings = get_settings()
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    settings.opencti_url,
                    headers={"Authorization": f"Bearer {settings.opencti_token}"},
                    json={"query": "{ serverInfo { version } }"},
                )
                latency = (time.time() - start) * 1000
                if response.status_code == 200:
                    return ComponentHealth(
                        name="opencti",
                        status=HealthStatus.HEALTHY,
                        message="OpenCTI connection successful",
                        latency_ms=latency,
                    )
                return ComponentHealth(
                    name="opencti",
                    status=HealthStatus.DEGRADED,
                    message=f"OpenCTI responded with status {response.status_code}",
                    latency_ms=latency,
                )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="opencti",
                status=HealthStatus.UNHEALTHY,
                message=f"OpenCTI connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def check_qdrant(self) -> ComponentHealth:
        """Check Qdrant connectivity."""
        start = time.time()
        try:
            import httpx
            settings = get_settings()
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{settings.qdrant_url}/collections")
                latency = (time.time() - start) * 1000
                if response.status_code == 200:
                    return ComponentHealth(
                        name="qdrant",
                        status=HealthStatus.HEALTHY,
                        message="Qdrant connection successful",
                        latency_ms=latency,
                    )
                return ComponentHealth(
                    name="qdrant",
                    status=HealthStatus.DEGRADED,
                    message=f"Qdrant responded with status {response.status_code}",
                    latency_ms=latency,
                )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="qdrant",
                status=HealthStatus.UNHEALTHY,
                message=f"Qdrant connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def check_vault(self) -> ComponentHealth:
        """Check Vault connectivity."""
        start = time.time()
        try:
            from .secrets import get_vault_client
            client = get_vault_client()
            client._get_client().is_authenticated()
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="vault",
                status=HealthStatus.HEALTHY,
                message="Vault connection successful",
                latency_ms=latency,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="vault",
                status=HealthStatus.UNHEALTHY,
                message=f"Vault connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def check_rabbitmq(self) -> ComponentHealth:
        """Check RabbitMQ connectivity."""
        start = time.time()
        try:
            import aio_pika
            settings = get_settings()
            connection = await aio_pika.connect_robust(settings.rabbitmq_url)
            await connection.close()
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="rabbitmq",
                status=HealthStatus.HEALTHY,
                message="RabbitMQ connection successful",
                latency_ms=latency,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return ComponentHealth(
                name="rabbitmq",
                status=HealthStatus.UNHEALTHY,
                message=f"RabbitMQ connection failed: {str(e)}",
                latency_ms=latency,
            )

    async def run_all_checks(self, components: Optional[List[str]] = None) -> HealthCheck:
        """Run all health checks."""
        checks = {
            "database": self.check_database,
            "redis": self.check_redis,
            "opensearch": self.check_opensearch,
            "wazuh": self.check_wazuh,
            "opencti": self.check_opencti,
            "qdrant": self.check_qdrant,
            "vault": self.check_vault,
            "rabbitmq": self.check_rabbitmq,
        }

        if components:
            checks = {k: v for k, v in checks.items() if k in components}

        results = await asyncio.gather(
            *checks.values(),
            return_exceptions=True,
        )

        component_healths = []
        for i, (name, check_fn) in enumerate(checks.items()):
            result = results[i]
            if isinstance(result, Exception):
                component_healths.append(ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Check failed: {str(result)}",
                ))
            elif isinstance(result, ComponentHealth):
                component_healths.append(result)

        # Determine overall status
        statuses = [c.status for c in component_healths]
        if all(s == HealthStatus.HEALTHY for s in statuses):
            overall_status = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall_status = HealthStatus.UNHEALTHY
        else:
            overall_status = HealthStatus.DEGRADED

        return HealthCheck(
            status=overall_status,
            version=self.version,
            uptime_seconds=time.time() - self._start_time,
            components=component_healths,
        )