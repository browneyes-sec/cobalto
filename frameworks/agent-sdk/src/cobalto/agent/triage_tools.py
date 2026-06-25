"""
Triage Agent Tools

Tools for initial alert assessment:
- MITRE RAG search: Find matching ATT&CK techniques
- Cortex enrichment: Enrich IOCs via Cortex analyzers
- VT lookup: VirusTotal indicator lookup
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool
import structlog

logger = structlog.get_logger(__name__)


class MITRERAGInput(BaseModel):
    """Input for MITRE RAG search."""
    query: str = Field(description="Search query for MITRE techniques")
    top_k: int = Field(default=5, description="Number of results to return")


@tool(args_schema=MITRERAGInput)
async def mitre_rag_search(query: str, top_k: int = 5) -> str:
    """
    Search MITRE ATT&CK techniques using RAG.

    Args:
        query: Search query (e.g., alert description, event type)
        top_k: Number of results to return (default: 5)

    Returns:
        List of matching MITRE techniques with tactics and scores
    """
    try:
        from qdrant_client import QdrantClient

        client = QdrantClient(url="http://localhost:6333")

        # Generate embedding (placeholder - in production use bge-m3)
        query_embedding = _generate_embedding(query)

        # Search in Qdrant
        results = client.search(
            collection_name="cobalto_mitre_attack",
            query_vector=query_embedding,
            limit=top_k,
        )

        techniques = []
        for result in results:
            payload = result.payload
            techniques.append({
                "technique_id": payload.get("technique_id", ""),
                "name": payload.get("name", ""),
                "tactics": payload.get("tactics", []),
                "score": round(result.score, 3),
            })

        logger.info(
            "mitre_rag_search_complete",
            query=query[:50],
            results_count=len(techniques),
        )

        return str(techniques)

    except Exception as e:
        logger.error("mitre_rag_search_failed", error=str(e))
        return str([])


class CortexEnrichInput(BaseModel):
    """Input for Cortex enrichment."""
    observable_type: str = Field(description="Type: ip, domain, hash, url, email")
    observable_value: str = Field(description="Value to enrich")


@tool(args_schema=CortexEnrichInput)
async def cortex_enrich(observable_type: str, observable_value: str) -> str:
    """
    Enrich an observable using Cortex (VirusTotal, AbuseIPDB, Shodan).

    Args:
        observable_type: Type of observable (ip, domain, hash, url, email)
        observable_value: Value to enrich

    Returns:
        Enrichment results from Cortex analyzers
    """
    try:
        import httpx

        # Call Cortex API
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:9001/api/analyzer/run",
                json={
                    "dataType": observable_type,
                    "data": observable_value,
                },
                timeout=30.0,
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    "cortex_enrichment_complete",
                    observable_type=observable_type,
                    observable_value=observable_value,
                )
                return str(result)
            else:
                logger.error(
                    "cortex_enrichment_failed",
                    status_code=response.status_code,
                )
                return str({"error": f"Cortex returned {response.status_code}"})

    except Exception as e:
        logger.error("cortex_enrichment_failed", error=str(e))
        return str({"error": str(e)})


class VTLookupInput(BaseModel):
    """Input for VirusTotal lookup."""
    indicator: str = Field(description="IP, domain, hash, or URL to lookup")


@tool(args_schema=VTLookupInput)
async def vt_lookup(indicator: str) -> str:
    """
    Look up an indicator on VirusTotal.

    Args:
        indicator: IP, domain, hash, or URL to lookup

    Returns:
        VirusTotal analysis results
    """
    try:
        import httpx

        # Determine indicator type
        if _is_ip(indicator):
            endpoint = f"ip_addresses/{indicator}"
        elif _is_hash(indicator):
            endpoint = f"files/{indicator}"
        elif _is_domain(indicator):
            endpoint = f"domains/{indicator}"
        elif _is_url(indicator):
            endpoint = f"urls/{indicator}"
        else:
            return str({"error": "Unknown indicator type"})

        # Call VirusTotal API (requires API key)
        # For now, return placeholder
        logger.info(
            "vt_lookup_placeholder",
            indicator=indicator,
        )

        return str({
            "indicator": indicator,
            "source": "virustotal",
            "status": "placeholder",
            "message": "VT API key required for full integration",
        })

    except Exception as e:
        logger.error("vt_lookup_failed", error=str(e))
        return str({"error": str(e)})


def _generate_embedding(text: str) -> List[float]:
    """Generate embedding for text (placeholder)."""
    import random
    # In production, use bge-m3 or OpenAI embeddings
    return [random.random() for _ in range(1024)]


def _is_ip(value: str) -> bool:
    """Check if value is an IP address."""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, value))


def _is_hash(value: str) -> bool:
    """Check if value is a hash (MD5, SHA1, SHA256)."""
    import re
    return bool(re.match(r'^[a-fA-F0-9]{32,64}$', value))


def _is_domain(value: str) -> bool:
    """Check if value is a domain."""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
    return bool(re.match(pattern, value))


def _is_url(value: str) -> bool:
    """Check if value is a URL."""
    return value.startswith(('http://', 'https://'))
