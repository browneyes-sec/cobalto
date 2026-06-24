"""
Collection management for Qdrant vector database.
Manages collections for different data types.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
from ..core.logging import get_logger

logger = get_logger(__name__)


class CollectionType(str, Enum):
    MITRE_ATTACK = "mitre_attack"
    THREAT_ACTORS = "threat_actors"
    INDICATORS = "indicators"
    AGENT_MEMORY = "agent_memory"
    DOCUMENTS = "documents"
    ALERTS = "alerts"


class CollectionConfig(BaseModel):
    """Configuration for a Qdrant collection."""
    name: str
    description: str = ""
    vector_size: int = 1536
    distance: str = "Cosine"
    on_disk: bool = False
    quantization_config: Optional[Dict[str, Any]] = None
    optimizer_config: Optional[Dict[str, Any]] = None


class CollectionManager:
    """Manages Qdrant collections."""

    # Pre-defined collection configurations
    COLLECTION_CONFIGS = {
        CollectionType.MITRE_ATTACK: CollectionConfig(
            name="cobalto_mitre_attack",
            description="MITRE ATT&CK technique embeddings for RAG",
            vector_size=1536,
        ),
        CollectionType.THREAT_ACTORS: CollectionConfig(
            name="cobalto_threat_actors",
            description="Threat actor profile embeddings",
            vector_size=1536,
        ),
        CollectionType.INDICATORS: CollectionConfig(
            name="cobalto_indicators",
            description="Indicator of Compromise embeddings",
            vector_size=1536,
        ),
        CollectionType.AGENT_MEMORY: CollectionConfig(
            name="cobalto_agent_memory",
            description="Agent long-term memory embeddings",
            vector_size=1536,
        ),
        CollectionType.DOCUMENTS: CollectionConfig(
            name="cobalto_documents",
            description="Document embeddings for knowledge base",
            vector_size=1536,
        ),
        CollectionType.ALERTS: CollectionConfig(
            name="cobalto_alerts",
            description="Alert embeddings for similarity search",
            vector_size=1536,
        ),
    }

    def __init__(self, qdrant_url: str, prefix: str = "cobalto"):
        self.qdrant_url = qdrant_url
        self.prefix = prefix
        self._client = None

    async def _get_client(self):
        """Get or create Qdrant client."""
        if self._client is None:
            from qdrant_client import QdrantClient
            self._client = QdrantClient(url=self.qdrant_url)
        return self._client

    async def create_collection(
        self,
        collection_type: CollectionType,
        config: Optional[CollectionConfig] = None,
    ) -> bool:
        """Create a new collection."""
        client = await self._get_client()
        cfg = config or self.COLLECTION_CONFIGS.get(collection_type)

        if not cfg:
            raise ValueError(f"No config for collection type: {collection_type}")

        try:
            from qdrant_client.models import VectorParams, Distance

            distance_map = {
                "Cosine": Distance.COSINE,
                "Euclid": Distance.EUCLID,
                "Dot": Distance.DOT,
            }

            client.create_collection(
                collection_name=cfg.name,
                vectors_config=VectorParams(
                    size=cfg.vector_size,
                    distance=distance_map.get(cfg.distance, Distance.COSINE),
                ),
                on_disk=cfg.on_disk,
            )

            logger.info("collection_created", collection=cfg.name)
            return True

        except Exception as e:
            logger.error("collection_create_failed", collection=cfg.name, error=str(e))
            return False

    async def delete_collection(self, collection_name: str) -> bool:
        """Delete a collection."""
        client = await self._get_client()
        try:
            client.delete_collection(collection_name=collection_name)
            logger.info("collection_deleted", collection=collection_name)
            return True
        except Exception as e:
            logger.error("collection_delete_failed", collection=collection_name, error=str(e))
            return False

    async def list_collections(self) -> List[Dict[str, Any]]:
        """List all collections."""
        client = await self._get_client()
        try:
            collections = client.get_collections()
            return [
                {
                    "name": c.name,
                    "vectors_count": c.vectors_count,
                    "points_count": c.points_count,
                    "status": c.status,
                }
                for c in collections.collections
                if c.name.startswith(self.prefix)
            ]
        except Exception as e:
            logger.error("list_collections_failed", error=str(e))
            return []

    async def get_collection_info(self, collection_name: str) -> Optional[Dict[str, Any]]:
        """Get collection information."""
        client = await self._get_client()
        try:
            info = client.get_collection(collection_name)
            return {
                "name": collection_name,
                "vectors_count": info.vectors_count,
                "points_count": info.points_count,
                "status": info.status,
                "optimizer_status": info.optimizer_status,
                "config": info.config,
            }
        except Exception as e:
            logger.error("get_collection_info_failed", collection=collection_name, error=str(e))
            return None

    async def insert_points(
        self,
        collection_name: str,
        points: List[Dict[str, Any]],
    ) -> bool:
        """Insert points into a collection."""
        client = await self._get_client()
        try:
            from qdrant_client.models import PointStruct

            point_structs = [
                PointStruct(
                    id=p["id"],
                    vector=p["vector"],
                    payload=p.get("payload", {}),
                )
                for p in points
            ]

            client.upsert(
                collection_name=collection_name,
                points=point_structs,
            )

            logger.info(
                "points_inserted",
                collection=collection_name,
                count=len(points),
            )
            return True

        except Exception as e:
            logger.error(
                "points_insert_failed",
                collection=collection_name,
                error=str(e),
            )
            return False

    async def search(
        self,
        collection_name: str,
        query_vector: List[float],
        limit: int = 10,
        score_threshold: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Search a collection."""
        client = await self._get_client()
        try:
            results = client.search(
                collection_name=collection_name,
                query_vector=query_vector,
                limit=limit,
                score_threshold=score_threshold,
            )

            return [
                {
                    "id": str(r.id),
                    "score": r.score,
                    "payload": r.payload,
                }
                for r in results
            ]

        except Exception as e:
            logger.error(
                "search_failed",
                collection=collection_name,
                error=str(e),
            )
            return []

    async def delete_points(
        self,
        collection_name: str,
        point_ids: List[str],
    ) -> bool:
        """Delete points from a collection."""
        client = await self._get_client()
        try:
            client.delete(
                collection_name=collection_name,
                points_selector=point_ids,
            )
            logger.info(
                "points_deleted",
                collection=collection_name,
                count=len(point_ids),
            )
            return True
        except Exception as e:
            logger.error(
                "delete_points_failed",
                collection=collection_name,
                error=str(e),
            )
            return False

    async def create_mitre_collection(self) -> bool:
        """Create the MITRE ATT&CK collection."""
        return await self.create_collection(CollectionType.MITRE_ATTACK)

    async def load_mitre_techniques(
        self,
        techniques: List[Dict[str, Any]],
        embeddings: List[List[float]],
    ) -> bool:
        """Load MITRE techniques with embeddings."""
        points = []
        for technique, embedding in zip(techniques, embeddings):
            points.append({
                "id": hash(technique.get("technique_id", "")) % (2**63),
                "vector": embedding,
                "payload": {
                    "content": f"{technique.get('name', '')} - {technique.get('description', '')}",
                    "metadata": {
                        "technique_id": technique.get("technique_id", ""),
                        "name": technique.get("name", ""),
                        "tactics": technique.get("tactics", []),
                        "platforms": technique.get("platforms", []),
                    },
                },
            })

        return await self.insert_points(
            self.COLLECTION_CONFIGS[CollectionType.MITRE_ATTACK].name,
            points,
        )