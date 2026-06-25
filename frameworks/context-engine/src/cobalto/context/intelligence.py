"""
Layer 3: Intelligence Context (RAG)

What do we know about this threat?
top_k MITRE techniques, OpenCTI indicators,
threat_actor_matches, CVE profiles
"""

from typing import Any, Dict, List, Optional
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue
import httpx
import structlog

logger = structlog.get_logger(__name__)


class IntelligenceLayer:
    """Loads threat intelligence via RAG."""

    def __init__(
        self,
        qdrant_url: str = "http://localhost:6333",
        opencti_url: Optional[str] = None,
        opencti_token: Optional[str] = None,
    ):
        self.qdrant_url = qdrant_url
        self.opencti_url = opencti_url
        self.opencti_token = opencti_token
        self._client: Optional[QdrantClient] = None

    async def _get_qdrant(self) -> QdrantClient:
        """Get or create Qdrant client."""
        if self._client is None:
            self._client = QdrantClient(url=self.qdrant_url)
        return self._client

    async def load(
        self,
        incident_id: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Load intelligence context via RAG."""
        logger.info("loading_intelligence_context", incident_id=incident_id)

        # Search MITRE techniques
        mitre_techniques = await self._search_mitre_techniques(alert_data)

        # Search OpenCTI indicators
        opencti_indicators = await self._search_opencti_indicators(alert_data)

        # Search threat actors
        threat_actors = await self._search_threat_actors(alert_data)

        # Search CVE profiles
        cve_profiles = await self._search_cves(alert_data)

        # Calculate confidence score
        confidence_score = self._calculate_confidence(
            mitre_techniques, opencti_indicators, threat_actors
        )

        return {
            "mitre_techniques": mitre_techniques,
            "opencti_indicators": opencti_indicators,
            "threat_actors": threat_actors,
            "cve_profiles": cve_profiles,
            "confidence_score": confidence_score,
            "intelligence_sources": self._get_intelligence_sources(
                mitre_techniques, opencti_indicators
            ),
        }

    async def _search_mitre_techniques(
        self, alert_data: Optional[Dict[str, Any]], top_k: int = 5
    ) -> List[Dict]:
        """RAG search for MITRE techniques."""
        if not alert_data:
            return []

        query = self._build_mitre_query(alert_data)

        try:
            client = await self._get_qdrant()

            # Generate embedding (using local model or API)
            query_embedding = await self._embed(query)

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
                    "description": payload.get("description", "")[:200],
                    "detection": payload.get("detection", ""),
                    "score": result.score,
                })

            logger.info(
                "mitre_search_complete",
                query=query[:50],
                results_count=len(techniques),
            )

            return techniques

        except Exception as e:
            logger.error("mitre_search_failed", error=str(e))
            # Fallback: return empty
            return []

    async def _search_opencti_indicators(
        self, alert_data: Optional[Dict[str, Any]], top_k: int = 5
    ) -> List[Dict]:
        """Search OpenCTI for indicator correlation."""
        if not self.opencti_url or not alert_data:
            return []

        indicators = self._extract_indicators(alert_data)
        if not indicators:
            return []

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.opencti_url}/graphql",
                    headers={"Authorization": f"Bearer {self.opencti_token}"},
                    json={
                        "query": """
                            query SearchIndicators($search: String!, $first: Int) {
                                indicators(search: $search, first: $first) {
                                    edges {
                                        node {
                                            id
                                            name
                                            pattern
                                            pattern_type
                                            confidence
                                            valid_from
                                        }
                                    }
                                }
                            }
                        """,
                        "variables": {"search": indicators[0], "first": top_k},
                    },
                    timeout=10.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    edges = data.get("data", {}).get("indicators", {}).get("edges", [])
                    return [
                        {
                            "id": e["node"]["id"],
                            "name": e["node"]["name"],
                            "pattern": e["node"]["pattern"],
                            "pattern_type": e["node"]["pattern_type"],
                            "confidence": e["node"]["confidence"],
                        }
                        for e in edges
                    ]

        except Exception as e:
            logger.error("opencti_search_failed", error=str(e))

        return []

    async def _search_threat_actors(self, alert_data: Optional[Dict[str, Any]]) -> List[Dict]:
        """Search for threat actors based on indicators."""
        # TODO: Implement threat actor correlation via OpenCTI
        return []

    async def _search_cves(self, alert_data: Optional[Dict[str, Any]]) -> List[Dict]:
        """Search for CVE profiles."""
        # TODO: Implement CVE search
        return []

    def _build_mitre_query(self, alert_data: Dict[str, Any]) -> str:
        """Build a search query from alert data."""
        parts = []
        if alert_data.get("rule_description"):
            parts.append(alert_data["rule_description"])
        if alert_data.get("event_type"):
            parts.append(alert_data["event_type"])
        if alert_data.get("source_ip"):
            parts.append(f"source IP {alert_data['source_ip']}")
        if alert_data.get("destination_ip"):
            parts.append(f"destination IP {alert_data['destination_ip']}")
        return " ".join(parts) if parts else "security alert"

    def _extract_indicators(self, alert_data: Dict[str, Any]) -> List[str]:
        """Extract indicators from alert data."""
        indicators = []
        for field in ["source_ip", "destination_ip", "user_name", "host_name"]:
            if alert_data.get(field):
                indicators.append(alert_data[field])
        return indicators

    async def _embed(self, text: str) -> List[float]:
        """Generate embedding for text."""
        # TODO: Use local embedding model (bge-m3) or OpenAI API
        # For now, return a placeholder random vector
        import random
        return [random.random() for _ in range(1024)]

    def _calculate_confidence(
        self,
        mitre: List[Dict],
        opencti: List[Dict],
        threat_actors: List[Dict],
    ) -> float:
        """Calculate overall intelligence confidence score."""
        if not mitre and not opencti and not threat_actors:
            return 0.0

        scores = []
        if mitre:
            scores.extend([t.get("score", 0) for t in mitre])
        if opencti:
            scores.extend([i.get("confidence", 0) / 100 for i in opencti])

        return sum(scores) / len(scores) if scores else 0.5

    def _get_intelligence_sources(
        self, mitre: List[Dict], opencti: List[Dict]
    ) -> List[str]:
        """Get list of intelligence sources used."""
        sources = []
        if mitre:
            sources.append("MITRE ATT&CK RAG")
        if opencti:
            sources.append("OpenCTI")
        return sources
