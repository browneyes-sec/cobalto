import os
import httpx
from typing import Optional


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


def _is_ip(indicator: str) -> bool:
    parts = indicator.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
