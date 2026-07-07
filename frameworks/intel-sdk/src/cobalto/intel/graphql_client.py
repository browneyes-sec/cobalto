"""
OpenCTI GraphQL client for threat intelligence queries.
Provides a high-level interface for querying the OpenCTI platform.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import httpx
from ..core.logging import get_logger
from ..core.metrics import record_external_request

logger = get_logger(__name__)


class GraphQLQuery(BaseModel):
    """GraphQL query definition."""
    query: str
    variables: Optional[Dict[str, Any]] = None


class GraphQLResponse(BaseModel):
    """GraphQL response."""
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[Dict[str, Any]]] = None


class OpenCTIClient:
    """Client for OpenCTI GraphQL API."""

    def __init__(
        self,
        url: str,
        token: str,
        timeout: float = 30.0,
    ):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        return self._client

    async def execute(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a GraphQL query."""
        client = await self._get_client()
        start_time = __import__("time").time()

        try:
            payload = {"query": query}
            if variables:
                payload["variables"] = variables

            response = await client.post("/graphql", json=payload)
            duration = __import__("time").time() - start_time

            record_external_request(
                "opencti",
                "graphql",
                "/graphql",
                str(response.status_code),
                duration,
            )

            response.raise_for_status()
            result = response.json()

            if "errors" in result:
                logger.error("graphql_errors", errors=result["errors"])

            return result

        except Exception as e:
            duration = __import__("time").time() - start_time
            record_external_request(
                "opencti",
                "graphql",
                "/graphql",
                "error",
                duration,
            )
            logger.exception("graphql_query_failed", error=str(e))
            raise

    async def close(self) -> None:
        """Close the client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    # Convenience methods

    async def get_server_info(self) -> Dict[str, Any]:
        """Get OpenCTI server information."""
        query = """
        query GetServerInfo {
            serverInfo {
                id
                version
                name
            }
        }
        """
        result = await self.execute(query)
        return result.get("data", {}).get("serverInfo", {})

    async def get_indicator(self, indicator_id: str) -> Optional[Dict[str, Any]]:
        """Get an indicator by ID."""
        query = """
        query GetIndicator($id: ID!) {
            indicator(id: $id) {
                id
                standard_id
                name
                description
                pattern
                pattern_type
                valid_from
                valid_until
                confidence
                x_opencti_score
                x_opencti_main_observable_type
                created
                updated
            }
        }
        """
        result = await self.execute(query, {"id": indicator_id})
        return result.get("data", {}).get("indicator")

    async def search_indicators(
        self,
        search: str,
        first: int = 50,
        after: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search for indicators."""
        query = """
        query SearchIndicators($search: String, $first: Int, $after: ID) {
            indicators(search: $search, first: $first, after: $after) {
                edges {
                    node {
                        id
                        name
                        pattern
                        pattern_type
                        confidence
                        x_opencti_score
                    }
                    cursor
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
            }
        }
        """
        result = await self.execute(query, {"search": search, "first": first, "after": after})
        return result.get("data", {}).get("indicators", {})

    async def get_mitre_attack_pattern(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get a MITRE ATT&CK technique."""
        query = """
        query GetAttackPattern($filters: Filter!) {
            attackPatterns(filters: $filters) {
                edges {
                    node {
                        id
                        name
                        description
                        x_mitre_id
                        x_mitre_detection
                        x_mitre_platforms
                        x_mitre_data_sources
                        killChainPhases {
                            chain_name
                            phase_name
                        }
                    }
                }
            }
        }
        """
        result = await self.execute(query, {
            "filters": {
                "key": "x_mitre_id",
                "values": [technique_id],
            }
        })
        edges = result.get("data", {}).get("attackPatterns", {}).get("edges", [])
        return edges[0]["node"] if edges else None

    async def get_threat_actor(self, actor_id: str) -> Optional[Dict[str, Any]]:
        """Get a threat actor."""
        query = """
        query GetThreatActor($id: ID!) {
            threatActor(id: $id) {
                id
                name
                description
                aliases
                first_seen
                last_seen
                goals
                sophistication
                resource_level
                primary_motivation
                roles
            }
        }
        """
        result = await self.execute(query, {"id": actor_id})
        return result.get("data", {}).get("threatActor")

    async def search_threat_actors(
        self,
        search: str,
        first: int = 50,
    ) -> Dict[str, Any]:
        """Search for threat actors."""
        query = """
        query SearchThreatActors($search: String, $first: Int) {
            threatActors(search: $search, first: $first) {
                edges {
                    node {
                        id
                        name
                        description
                        aliases
                        sophistication
                    }
                }
                totalCount
            }
        }
        """
        result = await self.execute(query, {"search": search, "first": first})
        return result.get("data", {}).get("threatActors", {})

    async def get_relationships(
        self,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        relationship_type: Optional[str] = None,
        first: int = 50,
    ) -> Dict[str, Any]:
        """Get relationships between objects."""
        query = """
        query GetRelationships(
            $sourceId: ID
            $targetId: ID
            $relationshipType: String
            $first: Int
        ) {
            stixCoreRelationships(
                fromId: $sourceId
                toId: $targetId
                relationship_type: $relationshipType
                first: $first
            ) {
                edges {
                    node {
                        id
                        relationship_type
                        description
                        start_time
                        stop_time
                        confidence
                        from {
                            id
                            entity_type
                            ... on ThreatActor {
                                name
                            }
                            ... on AttackPattern {
                                name
                            }
                            ... on Indicator {
                                name
                            }
                        }
                        to {
                            id
                            entity_type
                            ... on ThreatActor {
                                name
                            }
                            ... on AttackPattern {
                                name
                            }
                            ... on Indicator {
                                name
                            }
                        }
                    }
                }
                totalCount
            }
        }
        """
        result = await self.execute(query, {
            "sourceId": source_id,
            "targetId": target_id,
            "relationshipType": relationship_type,
            "first": first,
        })
        return result.get("data", {}).get("stixCoreRelationships", {})

    async def get_indicators_by_technique(
        self,
        technique_id: str,
        first: int = 100,
    ) -> Dict[str, Any]:
        """Get indicators associated with a MITRE technique."""
        query = """
        query GetIndicatorsByTechnique($techniqueId: ID!, $first: Int) {
            attackPattern(id: $techniqueId) {
                id
                name
                indicators(first: $first) {
                    edges {
                        node {
                            id
                            name
                            pattern
                            pattern_type
                            confidence
                            x_opencti_score
                        }
                    }
                }
            }
        }
        """
        result = await self.execute(query, {"techniqueId": technique_id, "first": first})
        return result.get("data", {}).get("attackPattern", {}).get("indicators", {})

    async def create_indicator(self, indicator_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new indicator."""
        query = """
        mutation CreateIndicator($input: IndicatorAddInput!) {
            indicatorAdd(input: $input) {
                id
                name
                pattern
            }
        }
        """
        result = await self.execute(query, {"input": indicator_data})
        return result.get("data", {}).get("indicatorAdd", {})

    async def update_score(
        self,
        entity_id: str,
        score: int,
    ) -> Dict[str, Any]:
        """Update the OpenCTI score for an entity."""
        query = """
        mutation UpdateScore($id: ID!, $score: Int!) {
            stixCoreObjectEdit(id: $id) {
                fieldPatch(input: {key: "x_opencti_score", value: $score})
            }
        }
        """
        result = await self.execute(query, {"id": entity_id, "score": score})
        return result.get("data", {})