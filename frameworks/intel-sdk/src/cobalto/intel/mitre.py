"""
MITRE ATT&CK mapping and RAG integration.
Provides technique identification and mapping for alerts.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import json
import httpx
from ..core.logging import get_logger

logger = get_logger(__name__)


class MITRETactic(BaseModel):
    """MITRE ATT&CK Tactic."""
    id: str
    name: str
    description: str = ""
    shortname: str = ""


class MITRTechnique(BaseModel):
    """MITRE ATT&CK Technique."""
    id: str
    technique_id: str
    name: str
    description: str = ""
    detection: str = ""
    platforms: List[str] = []
    data_sources: List[str] = []
    tactics: List[Dict[str, Any]] = []
    sub_techniques: List[str] = []
    is_sub_technique: bool = False
    external_references: List[Dict[str, Any]] = []


class MITREMapping(BaseModel):
    """Mapping of an alert to MITRE ATT&CK."""
    techniques: List[MITRTechnique] = []
    tactics: List[MITRETactic] = []
    confidence: float = 0.0
    coverage_score: float = 0.0
    recommendations: List[str] = []


class MITREMapper:
    """Maps alerts to MITRE ATT&CK techniques using RAG."""

    def __init__(
        self,
        qdrant_url: str,
        qdrant_collection: str = "mitre_attack",
        openai_api_key: Optional[str] = None,
    ):
        self.qdrant_url = qdrant_url
        self.qdrant_collection = qdrant_collection
        self.openai_api_key = openai_api_key
        self._techniques_cache: Dict[str, MITRTechnique] = {}
        self._tactics_cache: Dict[str, MITRETactic] = {}
        self._client = None

    async def _get_qdrant_client(self):
        """Get or create Qdrant client."""
        if self._client is None:
            from qdrant_client import QdrantClient
            self._client = QdrantClient(url=self.qdrant_url)
        return self._client

    async def load_techniques(self, techniques_file: str) -> None:
        """Load MITRE techniques from a JSON file."""
        try:
            with open(techniques_file, "r") as f:
                data = json.load(f)

            for technique_data in data.get("objects", []):
                if technique_data.get("type") == "attack-pattern":
                    # Extract technique ID from external references
                    technique_id = ""
                    for ref in technique_data.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            technique_id = ref.get("external_id", "")
                            break

                    technique = MITRTechnique(
                        id=technique_data.get("id", ""),
                        technique_id=technique_id,
                        name=technique_data.get("name", ""),
                        description=technique_data.get("description", ""),
                        detection=technique_data.get("x_mitre_detection", ""),
                        platforms=technique_data.get("x_mitre_platforms", []),
                        data_sources=technique_data.get("x_mitre_data_sources", []),
                        tactics=[
                            {
                                "tactic_id": phase.get("phase_name", ""),
                                "tactic_name": phase.get("phase_name", "").replace("-", " ").title(),
                            }
                            for phase in technique_data.get("kill_chain_phases", [])
                            if phase.get("chain_name") == "mitre-attack"
                        ],
                        is_sub_technique=technique_data.get("x_mitre_is_subtechnique", False),
                        external_references=technique_data.get("external_references", []),
                    )
                    self._techniques_cache[technique_id] = technique

            logger.info("mitre_techniques_loaded", count=len(self._techniques_cache))

        except Exception as e:
            logger.exception("mitre_load_failed", error=str(e))

    async def map_alert(
        self,
        alert_data: Dict[str, Any],
        top_k: int = 5,
    ) -> MITREMapping:
        """Map an alert to MITRE ATT&CK techniques using vector search."""
        try:
            # Build search query from alert
            search_query = self._build_search_query(alert_data)

            # Generate embedding
            embedding = await self._generate_embedding(search_query)

            if embedding is None:
                # Fallback to keyword search
                return await self._keyword_search(alert_data, top_k)

            # Vector search in Qdrant
            client = await self._get_qdrant_client()
            results = client.search(
                collection_name=self.qdrant_collection,
                query_vector=embedding,
                limit=top_k,
            )

            techniques = []
            tactics = set()

            for result in results:
                payload = result.payload
                technique_id = payload.get("technique_id", "")

                if technique_id in self._techniques_cache:
                    technique = self._techniques_cache[technique_id]
                    techniques.append(technique)
                    for tactic in technique.tactics:
                        tactics.add(tactic["tactic_id"])

            # Calculate confidence based on scores
            scores = [r.score for r in results]
            confidence = sum(scores) / len(scores) if scores else 0.0

            # Calculate coverage score
            coverage_score = len(techniques) / 10.0  # Normalize to 0-1

            # Generate recommendations
            recommendations = self._generate_recommendations(techniques)

            return MITREMapping(
                techniques=techniques,
                tactics=[
                    MITRETactic(
                        id=t,
                        name=t.replace("-", " ").title(),
                        shortname=t,
                    )
                    for t in tactics
                ],
                confidence=confidence,
                coverage_score=min(1.0, coverage_score),
                recommendations=recommendations,
            )

        except Exception as e:
            logger.exception("mitre_mapping_failed", error=str(e))
            return MITREMapping()

    async def _keyword_search(
        self,
        alert_data: Dict[str, Any],
        top_k: int,
    ) -> MITREMapping:
        """Fallback keyword-based search."""
        keywords = self._extract_keywords(alert_data)
        techniques = []
        tactics = set()

        for technique in self._techniques_cache.values():
            score = 0
            for keyword in keywords:
                if keyword.lower() in technique.name.lower():
                    score += 1
                if keyword.lower() in technique.description.lower():
                    score += 0.5

            if score > 0:
                techniques.append((score, technique))
                for tactic in technique.tactics:
                    tactics.add(tactic["tactic_id"])

        # Sort by score and take top_k
        techniques.sort(key=lambda x: x[0], reverse=True)
        top_techniques = [t[1] for t in techniques[:top_k]]

        confidence = techniques[0][0] / 5.0 if techniques else 0.0

        return MITREMapping(
            techniques=top_techniques,
            tactics=[
                MITRETactic(
                    id=t,
                    name=t.replace("-", " ").title(),
                    shortname=t,
                )
                for t in tactics
            ],
            confidence=min(1.0, confidence),
            coverage_score=min(1.0, len(top_techniques) / 10.0),
            recommendations=self._generate_recommendations(top_techniques),
        )

    async def _generate_embedding(self, text: str) -> Optional[List[float]]:
        """Generate embedding for text using OpenAI."""
        if not self.openai_api_key:
            return None

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.openai.com/v1/embeddings",
                    headers={
                        "Authorization": f"Bearer {self.openai_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "text-embedding-3-small",
                        "input": text,
                    },
                    timeout=10.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    return data["data"][0]["embedding"]
                return None

        except Exception as e:
            logger.error("embedding_generation_failed", error=str(e))
            return None

    def _build_search_query(self, alert_data: Dict[str, Any]) -> str:
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
        if alert_data.get("user_name"):
            parts.append(f"user {alert_data['user_name']}")

        return " ".join(parts) if parts else "security alert"

    def _extract_keywords(self, alert_data: Dict[str, Any]) -> List[str]:
        """Extract keywords from alert data."""
        keywords = []

        # From rule description
        desc = alert_data.get("rule_description", "")
        if desc:
            keywords.extend(desc.split()[:10])

        # From event type
        event_type = alert_data.get("event_type", "")
        if event_type:
            keywords.append(event_type)

        # Common attack keywords
        attack_keywords = [
            "brute", "force", "injection", "xss", "sqli", "command",
            "injection", "privilege", "escalation", "lateral", "movement",
            "exfiltration", "ransomware", "malware", "phishing",
        ]
        for keyword in attack_keywords:
            if keyword in str(alert_data).lower():
                keywords.append(keyword)

        return keywords

    def _generate_recommendations(self, techniques: List[MITRTechnique]) -> List[str]:
        """Generate recommendations based on techniques."""
        recommendations = []

        for technique in techniques:
            if technique.detection:
                recommendations.append(f"Detection: {technique.detection[:100]}...")

            # Add technique-specific recommendations
            if "T1110" in technique.technique_id:
                recommendations.append("Implement account lockout policies")
                recommendations.append("Enable multi-factor authentication")
            elif "T1059" in technique.technique_id:
                recommendations.append("Monitor command-line execution")
                recommendations.append("Implement application whitelisting")
            elif "T1071" in technique.technique_id:
                recommendations.append("Monitor network traffic for anomalies")
                recommendations.append("Implement DNS monitoring")

        return list(set(recommendations))[:5]

    def get_technique(self, technique_id: str) -> Optional[MITRTechnique]:
        """Get a technique by ID."""
        return self._techniques_cache.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> List[MITRTechnique]:
        """Get all techniques for a tactic."""
        return [
            t for t in self._techniques_cache.values()
            if any(ta["tactic_id"] == tactic for ta in t.tactics)
        ]

    def list_tactics(self) -> List[MITRETactic]:
        """List all tactics."""
        tactics = {}
        for technique in self._techniques_cache.values():
            for tactic in technique.tactics:
                tactic_id = tactic["tactic_id"]
                if tactic_id not in tactics:
                    tactics[tactic_id] = MITRETactic(
                        id=tactic_id,
                        name=tactic["tactic_name"],
                        shortname=tactic_id,
                    )
        return list(tactics.values())

    def get_technique_count(self) -> int:
        """Get the number of loaded techniques."""
        return len(self._techniques_cache)