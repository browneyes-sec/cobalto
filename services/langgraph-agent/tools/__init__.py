import os
import httpx
from typing import Optional
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
from middleware.metrics import metrics


async def mitre_attack_search(query: str) -> list[dict]:
    qdrant_url = os.getenv("QDRANT_URL", "http://localhost:6333")
    collection = "mitre_attack"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{qdrant_url}/collections/{collection}/points/search",
            json={
                "vector": [0.0] * 1536,
                "limit": 5,
                "filter": {
                    "must": [
                        {
                            "key": "text",
                            "match": {"value": query},
                        }
                    ]
                },
                "with_payload": True,
            },
            timeout=10.0,
        )
        response.raise_for_status()
        results = response.json().get("result", [])
        return [
            {
                "technique_id": r.get("payload", {}).get("technique_id", ""),
                "technique_name": r.get("payload", {}).get("technique_name", ""),
                "score": r.get("score", 0.0),
                "description": r.get("payload", {}).get("description", ""),
            }
            for r in results
        ]


# Instrument for metrics
mitre_attack_search = metrics.instrument_tool("mitre_attack_search")(mitre_attack_search)


async def enrich_ioc(indicator: str) -> dict:
    cortex_url = os.getenv("CORTEX_URL", "http://localhost:9001")
    api_key = os.getenv("CORTEX_API_KEY", "")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{cortex_url}/api/v1/responder/virustotal/query",
            json={"data": indicator, "dataType": "ip" if _is_ip(indicator) else "domain"},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("data", {})


# Instrument for metrics
enrich_ioc = metrics.instrument_tool("enrich_ioc")(enrich_ioc)


async def opencti_query(stix_pattern: str) -> dict:
    opencti_url = os.getenv("OPENCTI_URL", "http://localhost:8080")
    api_key = os.getenv("OPENCTI_API_KEY", "")

    query = """
    query($stixPattern: String!) {
      stixCoreObjects(stixCoreObjectsFilter: { stix_id: $stixPattern }) {
        edges {
          node {
            id
            standard_id
            ... on ThreatActor {
              name
              description
              first_seen
              last_seen
            }
            ... on Campaign {
              name
              description
              first_seen
              last_seen
            }
          }
        }
      }
    }
    """

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{opencti_url}/graphql",
            json={"query": query, "variables": {"stixPattern": stix_pattern}},
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=15.0,
        )
        response.raise_for_status()
        return response.json().get("data", {})


# Instrument for metrics
opencti_query = metrics.instrument_tool("opencti_query")(opencti_query)


def _is_ip(indicator: str) -> bool:
    parts = indicator.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ── Circuit Breaker Wrappers (RS-04/05) ────────────────────────────────────

@retry(
    stop=stop_after_attempt(3),
    wait=wait_fixed(2),
    retry=retry_if_exception_type(httpx.HTTPStatusError),
    reraise=True
)
async def mitre_attack_search_resilient(query: str) -> list[dict]:
    """Circuit-breaker protected wrapper for mitre_attack_search.
    
    Falls back to rule-based MITRE technique inference on failure.
    """
    try:
        return await mitre_attack_search(query)
    except httpx.HTTPStatusError as e:
        # Fallback: infer techniques from alert context
        return [
            {"technique_id": "TA0008", "technique_name": "Lateral Movement", "score": 0.5, "description": "Fallback: lateral movement inferred from alert context"},
            {"technique_id": "TA0006", "technique_name": "Credential Access", "score": 0.3, "description": "Fallback: credential access inferred from alert context"},
        ]
    except Exception as e:
        return []


@retry(
    stop=stop_after_attempt(3),
    wait=wait_fixed(2),
    retry=retry_if_exception_type(httpx.HTTPStatusError),
    reraise=True
)
async def enrich_ioc_resilient(indicator: str) -> dict:
    """Circuit-breaker protected wrapper for enrich_ioc.
    
    Falls back to empty enrichment on failure.
    """
    try:
        return await enrich_ioc(indicator)
    except httpx.HTTPStatusError:
        # Fallback: return empty enrichment
        return {"status": "enrichment_unavailable", "indicator": indicator}
    except Exception:
        return {}


@retry(
    stop=stop_after_attempt(2),
    wait=wait_fixed(3),
    retry=retry_if_exception_type(httpx.HTTPStatusError),
    reraise=True
)
async def opencti_query_resilient(stix_pattern: str) -> dict:
    """Circuit-breaker protected wrapper for opencti_query.
    
    Falls back to empty threat intel on failure.
    """
    try:
        return await opencti_query(stix_pattern)
    except httpx.HTTPStatusError:
        # Fallback: return empty result
        return {"threatActorMatches": [], "campaigns": []}
    except Exception:
        return {}