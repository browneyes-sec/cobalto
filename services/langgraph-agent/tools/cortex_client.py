import os
import re
import httpx
from typing import Optional
from enum import Enum


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    URL = "url"
    EMAIL = "email"
    UNKNOWN = "unknown"


class CortexClient:
    def __init__(self):
        self.url = os.getenv("CORTEX_URL", "http://localhost:9001")
        self.api_key = os.getenv("CORTEX_API_KEY", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def detect_ioc_type(self, indicator: str) -> IOCType:
        ip_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        )
        if ip_pattern.match(indicator):
            return IOCType.IP

        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", indicator):
            return IOCType.DOMAIN

        if re.match(r"^[a-fA-F0-9]{32}$", indicator):
            return IOCType.HASH_MD5
        if re.match(r"^[a-fA-F0-9]{40}$", indicator):
            return IOCType.HASH_SHA1
        if re.match(r"^[a-fA-F0-9]{64}$", indicator):
            return IOCType.HASH_SHA256

        if indicator.startswith(("http://", "https://")):
            return IOCType.URL

        if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", indicator):
            return IOCType.EMAIL

        return IOCType.UNKNOWN

    async def analyze_observable(
        self,
        indicator: str,
        analyzer: str = "VirusTotal",
    ) -> dict:
        ioc_type = self.detect_ioc_type(indicator)

        data_type_map = {
            IOCType.IP: "ip",
            IOCType.DOMAIN: "domain",
            IOCType.HASH_MD5: "hash",
            IOCType.HASH_SHA1: "hash",
            IOCType.HASH_SHA256: "hash",
            IOCType.URL: "url",
            IOCType.EMAIL: "email",
        }

        data_type = data_type_map.get(ioc_type, "unknown")
        if data_type == "unknown":
            return {"error": f"Unsupported IOC type: {ioc_type.value}", "indicator": indicator}

        payload = {
            "data": indicator,
            "dataType": data_type,
            "analyzerName": analyzer,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.url}/api/v1/responder/{analyzer.lower()}/run",
                json=payload,
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return {
                "job_id": response.json().get("id", ""),
                "status": response.json().get("status", ""),
                "data": response.json().get("data", {}),
                "ioc_type": ioc_type.value,
                "indicator": indicator,
            }

    async def get_report(self, job_id: str) -> dict:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.url}/api/v1/job/{job_id}",
                headers=self.headers,
                timeout=15.0,
            )
            response.raise_for_status()
            job_data = response.json()

            report = {}
            if job_data.get("status") == "Success" and job_data.get("report"):
                report = job_data["report"]

            return {
                "job_id": job_id,
                "status": job_data.get("status", ""),
                "report": report,
                "operations": job_data.get("operations", []),
            }

    async def analyze_and_wait(
        self,
        indicator: str,
        analyzer: str = "VirusTotal",
        timeout: int = 60,
    ) -> dict:
        import asyncio

        job_result = await self.analyze_observable(indicator, analyzer)
        job_id = job_result.get("job_id", "")

        if not job_id:
            return job_result

        elapsed = 0
        while elapsed < timeout:
            report = await self.get_report(job_id)
            if report.get("status") in ("Success", "Failure"):
                return report
            await asyncio.sleep(2)
            elapsed += 2

        return {"job_id": job_id, "status": "timeout", "report": {}}

    async def get_analyzers(self) -> list[dict]:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.url}/api/v1/analyzer",
                headers=self.headers,
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()
