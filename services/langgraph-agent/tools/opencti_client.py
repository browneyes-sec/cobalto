import os
import httpx
from typing import Optional


class OpenCTIClient:
    def __init__(self):
        self.url = os.getenv("OPENCTI_URL", "http://localhost:8080")
        self.api_key = os.getenv("OPENCTI_API_KEY", "")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def _graphql(self, query: str, variables: dict = None) -> dict:
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.url}/graphql",
                json=payload,
                headers=self.headers,
                timeout=15.0,
            )
            response.raise_for_status()
            return response.json().get("data", {})

    async def stix_pattern_search(self, stix_pattern: str) -> list[dict]:
        query = """
        query($pattern: String!) {
          stixCoreObjects(
            stixCoreObjectsFilter: { stix_id: $pattern }
          ) {
            edges {
              node {
                id
                standard_id
                entity_type
                ... on ThreatActor {
                  name
                  description
                  first_seen
                  last_seen
                  aliases
                }
                ... on Campaign {
                  name
                  description
                  first_seen
                  last_seen
                }
                ... on Malware {
                  name
                  description
                  malware_types
                }
                ... on Indicator {
                  name
                  pattern
                  pattern_type
                  valid_from
                }
              }
            }
          }
        }
        """
        data = await self._graphql(query, {"pattern": stix_pattern})
        edges = data.get("stixCoreObjects", {}).get("edges", [])
        return [edge["node"] for edge in edges]

    async def query_threat_actors(self, name_filter: Optional[str] = None) -> list[dict]:
        query = """
        query($name: String) {
          threatActors(
            filters: { name: $name }
          ) {
            edges {
              node {
                id
                name
                description
                first_seen
                last_seen
                aliases
                threat_actor_types
                sophistication
                primary_motivation
              }
            }
          }
        }
        """
        variables = {}
        if name_filter:
            variables["name"] = name_filter

        data = await self._graphql(query, variables)
        edges = data.get("threatActors", {}).get("edges", [])
        return [edge["node"] for edge in edges]

    async def query_campaigns(self, name_filter: Optional[str] = None) -> list[dict]:
        query = """
        query($name: String) {
          campaigns(
            filters: { name: $name }
          ) {
            edges {
              node {
                id
                name
                description
                first_seen
                last_seen
                objective
              }
            }
          }
        }
        """
        variables = {}
        if name_filter:
            variables["name"] = name_filter

        data = await self._graphql(query, variables)
        edges = data.get("campaigns", {}).get("edges", [])
        return [edge["node"] for edge in edges]

    async def query_malware_families(self, name_filter: Optional[str] = None) -> list[dict]:
        query = """
        query($name: String) {
          malwares(
            filters: { name: $name }
          ) {
            edges {
              node {
                id
                name
                description
                malware_types
                first_seen
                last_seen
                is_family
                kill_chain_phases {
                  kill_chain_name
                  phase_name
                }
              }
            }
          }
        }
        """
        variables = {}
        if name_filter:
            variables["name"] = name_filter

        data = await self._graphql(query, variables)
        edges = data.get("malwares", {}).get("edges", [])
        return [edge["node"] for edge in edges]

    async def get_indicator_by_pattern(self, pattern: str) -> Optional[dict]:
        query = """
        query($pattern: String!) {
          indicators(filters: { pattern: $pattern }) {
            edges {
              node {
                id
                name
                pattern
                pattern_type
                valid_from
                valid_until
                confidence
                markingDefinitions {
                  definition_type
                  definition
                }
              }
            }
          }
        }
        """
        data = await self._graphql(query, {"pattern": pattern})
        edges = data.get("indicators", {}).get("edges", [])
        return edges[0]["node"] if edges else None
