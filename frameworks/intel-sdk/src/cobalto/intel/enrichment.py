"""
Enrichment pipeline for observable analysis.
Orchestrates multiple enrichment sources for comprehensive analysis.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
import asyncio
from ..core.logging import get_logger
from ..core.metrics import record_enrichment

logger = get_logger(__name__)


class ObservableType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    USER = "user"
    HOSTNAME = "hostname"


class EnrichmentSource(str, Enum):
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    SHODAN = "shodan"
    MAXMIND = "maxmind"
    OTX = "otx"
    THREATFOX = "threatfox"
    MALWARE_BAZAAR = "malware_bazaar"
    URLHAUS = "urlhaus"


class EnrichmentResult(BaseModel):
    """Result from an enrichment source."""
    source: EnrichmentSource
    observable_type: ObservableType
    observable_value: str
    score: float = 0.0
    data: Dict[str, Any] = {}
    tags: List[str] = []
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0

    @property
    def is_malicious(self) -> bool:
        """Check if the enrichment indicates malicious activity."""
        return self.score >= 0.7

    @property
    def is_suspicious(self) -> bool:
        """Check if the enrichment indicates suspicious activity."""
        return 0.4 <= self.score < 0.7


class EnrichmentPipeline:
    """Pipeline for enriching observables from multiple sources."""

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        shodan_api_key: Optional[str] = None,
    ):
        self.virustotal_api_key = virustotal_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.shodan_api_key = shodan_api_key
        self._enrichers: Dict[EnrichmentSource, Any] = {}

    async def enrich_ip(self, ip_address: str) -> List[EnrichmentResult]:
        """Enrich an IP address from all available sources."""
        tasks = []

        if self.virustotal_api_key:
            tasks.append(self._enrich_virustotal(ObservableType.IP, ip_address))
        if self.abuseipdb_api_key:
            tasks.append(self._enrich_abuseipdb(ip_address))
        if self.shodan_api_key:
            tasks.append(self._enrich_shodan(ip_address))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        enrichment_results = []
        for result in results:
            if isinstance(result, EnrichmentResult):
                enrichment_results.append(result)
            elif isinstance(result, Exception):
                logger.error("enrichment_failed", observable=ip_address, error=str(result))

        return enrichment_results

    async def enrich_domain(self, domain: str) -> List[EnrichmentResult]:
        """Enrich a domain from all available sources."""
        tasks = []

        if self.virustotal_api_key:
            tasks.append(self._enrich_virustotal(ObservableType.DOMAIN, domain))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        enrichment_results = []
        for result in results:
            if isinstance(result, EnrichmentResult):
                enrichment_results.append(result)

        return enrichment_results

    async def enrich_hash(self, file_hash: str) -> List[EnrichmentResult]:
        """Enrich a file hash from all available sources."""
        tasks = []

        if self.virustotal_api_key:
            tasks.append(self._enrich_virustotal(ObservableType.HASH, file_hash))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        enrichment_results = []
        for result in results:
            if isinstance(result, EnrichmentResult):
                enrichment_results.append(result)

        return enrichment_results

    async def enrich_url(self, url: str) -> List[EnrichmentResult]:
        """Enrich a URL from all available sources."""
        tasks = []

        if self.virustotal_api_key:
            tasks.append(self._enrich_virustotal(ObservableType.URL, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        enrichment_results = []
        for result in results:
            if isinstance(result, EnrichmentResult):
                enrichment_results.append(result)

        return enrichment_results

    async def _enrich_virustotal(
        self,
        observable_type: ObservableType,
        value: str,
    ) -> EnrichmentResult:
        """Enrich using VirusTotal."""
        import httpx
        start_time = __import__("time").time()

        try:
            async with httpx.AsyncClient() as client:
                # Determine endpoint based on type
                type_map = {
                    ObservableType.IP: f"ip_addresses/{value}",
                    ObservableType.DOMAIN: f"domains/{value}",
                    ObservableType.HASH: f"files/{value}",
                    ObservableType.URL: f"urls/{value}",
                }
                endpoint = type_map.get(observable_type, f"ip_addresses/{value}")

                response = await client.get(
                    f"https://www.virustotal.com/api/v3/{endpoint}",
                    headers={"x-apikey": self.virustotal_api_key},
                    timeout=10.0,
                )

                duration = (__import__("time").time() - start_time) * 1000

                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})

                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 1
                    score = malicious / total if total > 0 else 0

                    tags = []
                    if malicious > 0:
                        tags.append("malicious")
                    if attributes.get("reputation", 0) < 0:
                        tags.append("low-reputation")

                    record_enrichment("webhook_handler", "virustotal", observable_type.value, "success", duration / 1000)

                    return EnrichmentResult(
                        source=EnrichmentSource.VIRUSTOTAL,
                        observable_type=observable_type,
                        observable_value=value,
                        score=score,
                        data={
                            "malicious": malicious,
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "reputation": attributes.get("reputation", 0),
                            "tags": attributes.get("tags", []),
                        },
                        tags=tags,
                        duration_ms=duration,
                    )
                else:
                    record_enrichment("webhook_handler", "virustotal", observable_type.value, "error", duration / 1000)
                    return EnrichmentResult(
                        source=EnrichmentSource.VIRUSTOTAL,
                        observable_type=observable_type,
                        observable_value=value,
                        error=f"HTTP {response.status_code}",
                        duration_ms=duration,
                    )

        except Exception as e:
            duration = (__import__("time").time() - start_time) * 1000
            record_enrichment("webhook_handler", "virustotal", observable_type.value, "error", duration / 1000)
            return EnrichmentResult(
                source=EnrichmentSource.VIRUSTOTAL,
                observable_type=observable_type,
                observable_value=value,
                error=str(e),
                duration_ms=duration,
            )

    async def _enrich_abuseipdb(self, ip_address: str) -> EnrichmentResult:
        """Enrich using AbuseIPDB."""
        import httpx
        start_time = __import__("time").time()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    timeout=10.0,
                )

                duration = (__import__("time").time() - start_time) * 1000

                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0) / 100

                    tags = []
                    if score >= 0.7:
                        tags.append("malicious")
                    if data.get("isPublic"):
                        tags.append("public-ip")
                    if data.get("isWhitelisted"):
                        tags.append("whitelisted")

                    record_enrichment("webhook_handler", "abuseipdb", "ip", "success", duration / 1000)

                    return EnrichmentResult(
                        source=EnrichmentSource.ABUSEIPDB,
                        observable_type=ObservableType.IP,
                        observable_value=ip_address,
                        score=score,
                        data={
                            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                            "total_reports": data.get("totalReports", 0),
                            "num_distinct_users": data.get("numDistinctUsers", 0),
                            "last_reported_at": data.get("lastReportedAt"),
                            "is_public": data.get("isPublic", False),
                            "is_whitelisted": data.get("isWhitelisted", False),
                            "usage_type": data.get("usageType"),
                            "isp": data.get("isp"),
                            "country_code": data.get("countryCode"),
                        },
                        tags=tags,
                        duration_ms=duration,
                    )
                else:
                    record_enrichment("webhook_handler", "abuseipdb", "ip", "error", duration / 1000)
                    return EnrichmentResult(
                        source=EnrichmentSource.ABUSEIPDB,
                        observable_type=ObservableType.IP,
                        observable_value=ip_address,
                        error=f"HTTP {response.status_code}",
                        duration_ms=duration,
                    )

        except Exception as e:
            duration = (__import__("time").time() - start_time) * 1000
            record_enrichment("webhook_handler", "abuseipdb", "ip", "error", duration / 1000)
            return EnrichmentResult(
                source=EnrichmentSource.ABUSEIPDB,
                observable_type=ObservableType.IP,
                observable_value=ip_address,
                error=str(e),
                duration_ms=duration,
            )

    async def _enrich_shodan(self, ip_address: str) -> EnrichmentResult:
        """Enrich using Shodan."""
        import httpx
        start_time = __import__("time").time()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip_address}",
                    params={"key": self.shodan_api_key},
                    timeout=10.0,
                )

                duration = (__import__("time").time() - start_time) * 1000

                if response.status_code == 200:
                    data = response.json()

                    # Calculate score based on open ports and vulnerabilities
                    ports = data.get("ports", [])
                    vulns = data.get("vulns", [])
                    score = min(1.0, (len(ports) * 0.1 + len(vulns) * 0.2))

                    tags = []
                    if vulns:
                        tags.append("has-vulns")
                    if len(ports) > 10:
                        tags.append("many-open-ports")

                    record_enrichment("webhook_handler", "shodan", "ip", "success", duration / 1000)

                    return EnrichmentResult(
                        source=EnrichmentSource.SHODAN,
                        observable_type=ObservableType.IP,
                        observable_value=ip_address,
                        score=score,
                        data={
                            "ports": ports,
                            "vulns": vulns,
                            "os": data.get("os"),
                            "org": data.get("org"),
                            "isp": data.get("isp"),
                            "country_code": data.get("country_code"),
                            "hostnames": data.get("hostnames", []),
                            "domains": data.get("domains", []),
                        },
                        tags=tags,
                        duration_ms=duration,
                    )
                else:
                    record_enrichment("webhook_handler", "shodan", "ip", "error", duration / 1000)
                    return EnrichmentResult(
                        source=EnrichmentSource.SHODAN,
                        observable_type=ObservableType.IP,
                        observable_value=ip_address,
                        error=f"HTTP {response.status_code}",
                        duration_ms=duration,
                    )

        except Exception as e:
            duration = (__import__("time").time() - start_time) * 1000
            record_enrichment("webhook_handler", "shodan", "ip", "error", duration / 1000)
            return EnrichmentResult(
                source=EnrichmentSource.SHODAN,
                observable_type=ObservableType.IP,
                observable_value=ip_address,
                error=str(e),
                duration_ms=duration,
            )

    def aggregate_results(self, results: List[EnrichmentResult]) -> Dict[str, Any]:
        """Aggregate enrichment results into a summary."""
        if not results:
            return {
                "score": 0.0,
                "is_malicious": False,
                "is_suspicious": False,
                "sources": [],
                "tags": [],
            }

        # Calculate aggregate score
        scores = [r.score for r in results if r.error is None]
        avg_score = sum(scores) / len(scores) if scores else 0.0

        # Aggregate tags
        all_tags = []
        for r in results:
            all_tags.extend(r.tags)
        unique_tags = list(set(all_tags))

        # Check for malicious/suspicious
        is_malicious = any(r.is_malicious for r in results)
        is_suspicious = any(r.is_suspicious for r in results)

        return {
            "score": avg_score,
            "is_malicious": is_malicious,
            "is_suspicious": is_suspicious,
            "sources": [r.source.value for r in results if r.error is None],
            "tags": unique_tags,
            "details": {r.source.value: r.data for r in results if r.error is None},
            "errors": [r.error for r in results if r.error is not None],
        }