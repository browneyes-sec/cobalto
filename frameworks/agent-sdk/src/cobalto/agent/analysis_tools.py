"""
Analysis Agent Tools

Tools for deep alert analysis:
- OpenCTI GraphQL: Query threat intelligence
- MISP Correlate: Correlate IOCs with MISP events
- ES Query: Search Elasticsearch for related logs
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool
import structlog

logger = structlog.get_logger(__name__)


class OpenCTIQueryInput(BaseModel):
    """Input for OpenCTI GraphQL query."""
    query_type: str = Field(description="Type: indicator, threat_actor, attack_pattern, vulnerability")
    search_term: str = Field(description="Search term or ID")
    limit: int = Field(default=10, description="Number of results")


@tool(args_schema=OpenCTIQueryInput)
async def opencti_query(query_type: str, search_term: str, limit: int = 10) -> str:
    """
    Query OpenCTI for threat intelligence via GraphQL.

    Args:
        query_type: Type of entity (indicator, threat_actor, attack_pattern, vulnerability)
        search_term: Search term or ID
        limit: Number of results (default: 10)

    Returns:
        Query results from OpenCTI
    """
    try:
        import httpx

        # Build GraphQL query based on type
        queries = {
            "indicator": """
                query SearchIndicators($search: String!, $first: Int) {
                    indicators(search: $search, first: $first) {
                        edges {
                            node {
                                id name pattern pattern_type confidence
                                valid_from created_at updated_at
                            }
                        }
                    }
                }
            """,
            "threat_actor": """
                query SearchThreatActors($search: String!, $first: Int) {
                    threatActors(search: $search, first: $first) {
                        edges {
                            node {
                                id name description aliases
                                first_seen last_seen sophistication goals
                            }
                        }
                    }
                }
            """,
            "attack_pattern": """
                query SearchAttackPatterns($search: String!, $first: Int) {
                    attackPatterns(search: $search, first: $first) {
                        edges {
                            node {
                                id name description x_mitre_id
                                x_mitre_tactics { id name }
                                x_mitre_platforms
                            }
                        }
                    }
                }
            """,
            "vulnerability": """
                query SearchVulnerabilities($search: String!, $first: Int) {
                    vulnerabilities(search: $search, first: $first) {
                        edges {
                            node {
                                id name description
                                x_opencti_cvss_base_score
                                x_opencti_stix_id
                            }
                        }
                    }
                }
            """,
        }

        query = queries.get(query_type)
        if not query:
            return str({"error": f"Unknown query type: {query_type}"})

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:4000/graphql",
                headers={
                    "Authorization": "Bearer d41d8cd98f00b204e9800998ecf8427e",
                    "Content-Type": "application/json",
                },
                json={
                    "query": query,
                    "variables": {"search": search_term, "first": limit},
                },
                timeout=15.0,
            )

            if response.status_code == 200:
                data = response.json()
                logger.info(
                    "opencti_query_complete",
                    query_type=query_type,
                    search_term=search_term,
                )
                return str(data.get("data", {}))
            else:
                logger.error("opencti_query_failed", status_code=response.status_code)
                return str({"error": f"OpenCTI returned {response.status_code}"})

    except Exception as e:
        logger.error("opencti_query_failed", error=str(e))
        return str({"error": str(e)})


class MISPCorrelateInput(BaseModel):
    """Input for MISP correlation."""
    ioc_type: str = Field(description="Type: ip, domain, hash, url, email")
    ioc_value: str = Field(description="IOC value to correlate")


@tool(args_schema=MISPCorrelateInput)
async def misp_correlate(ioc_type: str, ioc_value: str) -> str:
    """
    Correlate an IOC with MISP events.

    Args:
        ioc_type: Type of IOC (ip, domain, hash, url, email)
        ioc_value: IOC value to correlate

    Returns:
        Correlated MISP events
    """
    try:
        import httpx

        # Map IOC type to MISP object type
        misp_types = {
            "ip": "ip-dst",
            "domain": "domain",
            "hash": "sha256",
            "url": "url",
            "email": "email-src",
        }

        misp_type = misp_types.get(ioc_type, ioc_type)

        # Search MISP for events containing this IOC
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8080/events/restSearch",
                headers={
                    "Authorization": "admin@cobalto.local",
                    "Accept": "Application/json",
                    "Content-Type": "application/json",
                },
                json={
                    "value": ioc_value,
                    "type": misp_type,
                },
                timeout=15.0,
            )

            if response.status_code == 200:
                data = response.json()
                events = data.get("response", [])
                logger.info(
                    "misp_correlate_complete",
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    events_count=len(events),
                )
                return str({
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "events": events[:5],  # Limit to 5 events
                    "total_events": len(events),
                })
            else:
                logger.error("misp_correlate_failed", status_code=response.status_code)
                return str({"error": f"MISP returned {response.status_code}"})

    except Exception as e:
        logger.error("misp_correlate_failed", error=str(e))
        return str({"error": str(e)})


class ESQueryInput(BaseModel):
    """Input for Elasticsearch query."""
    index: str = Field(default="wazuh-*", description="Elasticsearch index")
    query: str = Field(description="KQL or Lucene query")
    time_range: str = Field(default="24h", description="Time range (1h, 24h, 7d)")
    limit: int = Field(default=100, description="Max results")


@tool(args_schema=ESQueryInput)
async def es_query(index: str, query: str, time_range: str = "24h", limit: int = 100) -> str:
    """
    Search Elasticsearch for related logs.

    Args:
        index: Elasticsearch index (default: wazuh-*)
        query: KQL or Lucene query
        time_range: Time range (1h, 24h, 7d)
        limit: Max results (default: 100)

    Returns:
        Search results from Elasticsearch
    """
    try:
        import httpx

        # Convert time range to milliseconds
        time_map = {
            "1h": "now-1h",
            "24h": "now-24h",
            "7d": "now-7d",
            "30d": "now-30d",
        }

        gte = time_map.get(time_range, "now-24h")

        # Build Elasticsearch query
        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}}
                    ],
                    "filter": [
                        {"range": {"@timestamp": {"gte": gte, "lte": "now"}}}
                    ]
                }
            },
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"http://localhost:9200/{index}/_search",
                headers={"Content-Type": "application/json"},
                json=es_query,
                timeout=15.0,
            )

            if response.status_code == 200:
                data = response.json()
                hits = data.get("hits", {}).get("hits", [])
                total = data.get("hits", {}).get("total", {}).get("value", 0)

                logger.info(
                    "es_query_complete",
                    index=index,
                    query=query[:50],
                    results_count=len(hits),
                    total=total,
                )

                return str({
                    "index": index,
                    "query": query,
                    "time_range": time_range,
                    "total": total,
                    "results": [h.get("_source", {}) for h in hits[:10]],  # Limit returned
                })
            else:
                logger.error("es_query_failed", status_code=response.status_code)
                return str({"error": f"Elasticsearch returned {response.status_code}"})

    except Exception as e:
        logger.error("es_query_failed", error=str(e))
        return str({"error": str(e)})
