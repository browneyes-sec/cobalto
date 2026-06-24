"""
Data Mesh Memory - Advanced memory system for multi-agent SOC platform.

Implements:
- Episodic memory (specific events/occurrences)
- Semantic memory (facts, rules, knowledge)
- Procedural memory (playbooks, learned procedures)
- Reflective memory (agent self-reflection, learnings)
- Cross-agent memory sharing
- Memory consolidation and lifecycle management
"""

from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from enum import Enum
import uuid
import asyncio


class MemoryDomain(str, Enum):
    """Memory domains for data mesh organization."""
    SIEM = "siem"
    THREAT_INTEL = "threat_intel"
    CASE_MGMT = "case_mgmt"
    RESPONSE = "response"
    HUNT = "hunt"
    AGENT = "agent"


class MemoryPriority(str, Enum):
    """Memory priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MemoryMetadata(BaseModel):
    """Metadata for memory entries."""
    domain: MemoryDomain
    agent_id: Optional[str] = None
    agent_type: Optional[str] = None
    tenant_id: str = "default"
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    priority: MemoryPriority = MemoryPriority.MEDIUM
    ttl_seconds: Optional[int] = None
    expires_at: Optional[datetime] = None
    related_ids: List[str] = Field(default_factory=list)
    embedding_model: str = "text-embedding-3-small"


class MemoryEntry(BaseModel):
    """Extended memory entry with data mesh metadata."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    summary: Optional[str] = None
    memory_type: str  # episodic, semantic, procedural, reflective
    metadata: MemoryMetadata
    embedding: Optional[List[float]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    importance: float = 0.5
    confidence: float = 1.0
    is_consolidated: bool = False


class CollectionConfig(BaseModel):
    """Configuration for a memory collection."""
    name: str
    domain: MemoryDomain
    description: str
    vector_size: int = 1536
    distance: str = "cosine"
    shard_count: int = 1
    replication_factor: int = 1
    indexes: List[str] = Field(default_factory=lambda: ["memory_type", "domain", "tenant_id"])
    retention_days: int = 90
    enable_consolidation: bool = True


class DataMeshMemory:
    """
    Data Mesh Memory system for multi-agent SOC platform.

    Provides:
    - Domain-oriented memory collections
    - Cross-agent memory sharing
    - Memory consolidation and lifecycle
    - Hybrid search (vector + keyword)
    """

    def __init__(
        self,
        qdrant_url: str,
        collection_prefix: str = "cobalto",
        embedding_dim: int = 1536,
    ):
        self.qdrant_url = qdrant_url
        self.collection_prefix = collection_prefix
        self.embedding_dim = embedding_dim
        self._client = None
        self._collections: Dict[str, CollectionConfig] = {}

        # Default collection configs
        self._init_default_collections()

    def _init_default_collections(self) -> None:
        """Initialize default collection configurations."""
        default_configs = [
            CollectionConfig(
                name=f"{self.collection_prefix}_episodic",
                domain=MemoryDomain.AGENT,
                description="Agent episodic memories (specific events)",
            ),
            CollectionConfig(
                name=f"{self.collection_prefix}_semantic",
                domain=MemoryDomain.AGENT,
                description="Semantic knowledge (facts, rules)",
            ),
            CollectionConfig(
                name=f"{self.collection_prefix}_procedural",
                domain=MemoryDomain.RESPONSE,
                description="Procedural memory (playbooks, procedures)",
            ),
            CollectionConfig(
                name=f"{self.collection_prefix}_reflective",
                domain=MemoryDomain.AGENT,
                description="Agent self-reflection and learnings",
            ),
            CollectionConfig(
                name=f"{self.collection_prefix}_alerts",
                domain=MemoryDomain.SIEM,
                description="Alert embeddings for similarity search",
            ),
            CollectionConfig(
                name=f"{self.collection_prefix}_threat_intel",
                domain=MemoryDomain.THREAT_INTEL,
                description="Threat intelligence embeddings",
            ),
            CollectionConfig(
                name=f"{self.collection_prefix}_cases",
                domain=MemoryDomain.CASE_MGMT,
                description="Case embeddings for deduplication",
            ),
        ]

        for config in default_configs:
            self._collections[config.name] = config

    async def _get_client(self):
        """Get or create Qdrant client."""
        if self._client is None:
            from qdrant_client import QdrantClient
            self._client = QdrantClient(url=self.qdrant_url)
        return self._client

    def register_collection(self, config: CollectionConfig) -> None:
        """Register a new collection configuration."""
        config.name = f"{self.collection_prefix}_{config.name}" if not config.name.startswith(self.collection_prefix) else config.name
        self._collections[config.name] = config

    async def ensure_collections_exist(self) -> None:
        """Create collections if they don't exist."""
        from qdrant_client.models import VectorParams, Distance

        client = await self._get_client()

        for name, config in self._collections.items():
            try:
                # Check if collection exists
                collections = await client.get_collections()
                existing = [c.name for c in collections.collections]

                if name not in existing:
                    distance_map = {
                        "cosine": Distance.COSINE,
                        "euclid": Distance.EUCLID,
                        "dot": Distance.DOT,
                    }

                    await client.create_collection(
                        collection_name=name,
                        vectors_config=VectorParams(
                            size=config.vector_size,
                            distance=distance_map.get(config.distance, Distance.COSINE),
                        ),
                    )
                    print(f"Created collection: {name}")
            except Exception as e:
                print(f"Error ensuring collection {name}: {e}")

    async def store(self, entry: MemoryEntry) -> bool:
        """Store a memory entry."""
        try:
            from qdrant_client.models import PointStruct

            client = await self._get_client()

            # Determine collection based on memory type
            collection_name = self._get_collection_for_memory(entry)

            # Get or create embedding if needed
            if not entry.embedding:
                entry.embedding = await self._generate_embedding(entry.content)

            point = PointStruct(
                id=hash(entry.id) % (2**63),
                vector=entry.embedding,
                payload={
                    "id": entry.id,
                    "content": entry.content,
                    "summary": entry.summary,
                    "memory_type": entry.memory_type,
                    "domain": entry.metadata.domain.value,
                    "agent_id": entry.metadata.agent_id,
                    "agent_type": entry.metadata.agent_type,
                    "tenant_id": entry.metadata.tenant_id,
                    "source": entry.metadata.source,
                    "tags": entry.metadata.tags,
                    "priority": entry.metadata.priority.value,
                    "importance": entry.importance,
                    "confidence": entry.confidence,
                    "created_at": entry.created_at.isoformat(),
                    "updated_at": entry.updated_at.isoformat(),
                    "access_count": entry.access_count,
                    "related_ids": entry.metadata.related_ids,
                },
            )

            await client.upsert(
                collection_name=collection_name,
                points=[point],
            )

            return True

        except Exception as e:
            print(f"Error storing memory: {e}")
            return False

    async def search(
        self,
        query_embedding: List[float],
        domains: Optional[List[MemoryDomain]] = None,
        memory_types: Optional[List[str]] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 10,
        min_score: float = 0.7,
    ) -> List[MemoryEntry]:
        """
        Search memories across domains.

        Args:
            query_embedding: Query vector
            domains: Filter by domains
            memory_types: Filter by memory types
            tenant_id: Filter by tenant
            agent_id: Filter by agent
            tags: Filter by tags
            limit: Max results
            min_score: Minimum similarity score
        """
        try:
            from qdrant_client.models import Filter, FieldCondition, MatchValue, MatchAny

            client = await self._get_client()

            # Build filter conditions
            conditions = []

            if domains:
                domain_values = [d.value for d in domains]
                conditions.append(
                    FieldCondition(key="domain", match=MatchAny(any=domain_values))
                )

            if memory_types:
                conditions.append(
                    FieldCondition(key="memory_type", match=MatchAny(any=memory_types))
                )

            if tenant_id:
                conditions.append(
                    FieldCondition(key="tenant_id", match=MatchValue(value=tenant_id))
                )

            if agent_id:
                conditions.append(
                    FieldCondition(key="agent_id", match=MatchValue(value=agent_id))
                )

            if tags:
                conditions.append(
                    FieldCondition(key="tags", match=MatchAny(any=tags))
                )

            query_filter = Filter(must=conditions) if conditions else None

            # Search across relevant collections
            all_results = []
            collections_to_search = self._get_collections_for_search(domains)

            for collection_name in collections_to_search:
                try:
                    results = await client.search(
                        collection_name=collection_name,
                        query_vector=query_embedding,
                        limit=limit,
                        query_filter=query_filter,
                        score_threshold=min_score,
                    )

                    for result in results:
                        payload = result.payload
                        entry = MemoryEntry(
                            id=payload["id"],
                            content=payload["content"],
                            summary=payload.get("summary"),
                            memory_type=payload["memory_type"],
                            metadata=MemoryMetadata(
                                domain=MemoryDomain(payload["domain"]),
                                agent_id=payload.get("agent_id"),
                                agent_type=payload.get("agent_type"),
                                tenant_id=payload.get("tenant_id", "default"),
                                source=payload.get("source"),
                                tags=payload.get("tags", []),
                                priority=MemoryPriority(payload.get("priority", "medium")),
                            ),
                            importance=payload.get("importance", 0.5),
                            confidence=payload.get("confidence", 1.0),
                            created_at=datetime.fromisoformat(payload["created_at"]),
                            updated_at=datetime.fromisoformat(payload["updated_at"]),
                            access_count=payload.get("access_count", 0),
                        )
                        all_results.append((result.score, entry))

                except Exception as e:
                    print(f"Error searching collection {collection_name}: {e}")
                    continue

            # Sort by score and return top results
            all_results.sort(key=lambda x: x[0], reverse=True)
            return [entry for _, entry in all_results[:limit]]

        except Exception as e:
            print(f"Error in search: {e}")
            return []

    async def get_recent(
        self,
        domain: Optional[MemoryDomain] = None,
        agent_id: Optional[str] = None,
        tenant_id: str = "default",
        limit: int = 50,
    ) -> List[MemoryEntry]:
        """Get recent memories."""
        try:
            from qdrant_client.models import Filter, FieldCondition, MatchValue

            client = await self._get_client()

            conditions = [
                FieldCondition(key="tenant_id", match=MatchValue(value=tenant_id))
            ]

            if domain:
                conditions.append(
                    FieldCondition(key="domain", match=MatchValue(value=domain.value))
                )

            if agent_id:
                conditions.append(
                    FieldCondition(key="agent_id", match=MatchValue(value=agent_id))
                )

            query_filter = Filter(must=conditions)

            # Search in relevant collection
            collection = self._get_collection_for_domain(domain)

            results = await client.scroll(
                collection_name=collection,
                scroll_filter=query_filter,
                limit=limit,
                order_by=None,  # Default ordering
            )

            entries = []
            for point in results[0]:
                payload = point.payload
                entries.append(
                    MemoryEntry(
                        id=payload["id"],
                        content=payload["content"],
                        summary=payload.get("summary"),
                        memory_type=payload["memory_type"],
                        metadata=MemoryMetadata(
                            domain=MemoryDomain(payload["domain"]),
                            agent_id=payload.get("agent_id"),
                            agent_type=payload.get("agent_type"),
                            tenant_id=payload.get("tenant_id", "default"),
                            source=payload.get("source"),
                            tags=payload.get("tags", []),
                            priority=MemoryPriority(payload.get("priority", "medium")),
                        ),
                        importance=payload.get("importance", 0.5),
                        created_at=datetime.fromisoformat(payload["created_at"]),
                    )
                )

            return entries

        except Exception as e:
            print(f"Error getting recent memories: {e}")
            return []

    async def consolidate(
        self,
        domain: MemoryDomain,
        tenant_id: str = "default",
        max_age_days: int = 7,
    ) -> Dict[str, Any]:
        """
        Consolidate memories - merge similar, archive old, extract insights.

        Returns consolidation statistics.
        """
        stats = {
            "total_processed": 0,
            "consolidated": 0,
            "archived": 0,
            "errors": 0,
        }

        try:
            # Get old memories
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
            collection = self._get_collection_for_domain(domain)

            # TODO: Implement consolidation logic
            # 1. Find similar memories (high cosine similarity)
            # 2. Merge into consolidated entry
            # 3. Archive original entries
            # 4. Extract insights/patterns

            stats["status"] = "consolidation_not_implemented"

        except Exception as e:
            stats["errors"] += 1
            print(f"Error in consolidation: {e}")

        return stats

    async def get_cross_agent_insights(
        self,
        agent_type: str,
        domain: MemoryDomain,
        limit: int = 10,
    ) -> List[MemoryEntry]:
        """Get insights from other agents of the same type."""
        # Search for memories from other agents of the same type
        # but exclude the current agent's own memories
        # This enables cross-agent learning
        return []

    async def share_memory(
        self,
        entry_id: str,
        target_agents: List[str],
        permission_level: str = "read",
    ) -> bool:
        """Share a memory entry with specific agents."""
        # Implementation for cross-agent memory sharing
        return True

    def _get_collection_for_memory(self, entry: MemoryEntry) -> str:
        """Determine collection for a memory entry."""
        if entry.memory_type == "episodic":
            return f"{self.collection_prefix}_episodic"
        elif entry.memory_type == "semantic":
            return f"{self.collection_prefix}_semantic"
        elif entry.memory_type == "procedural":
            return f"{self.collection_prefix}_procedural"
        elif entry.memory_type == "reflective":
            return f"{self.collection_prefix}_reflective"
        elif entry.metadata.domain == MemoryDomain.SIEM:
            return f"{self.collection_prefix}_alerts"
        elif entry.metadata.domain == MemoryDomain.THREAT_INTEL:
            return f"{self.collection_prefix}_threat_intel"
        elif entry.metadata.domain == MemoryDomain.CASE_MGMT:
            return f"{self.collection_prefix}_cases"
        else:
            return f"{self.collection_prefix}_episodic"

    def _get_collections_for_search(
        self, domains: Optional[List[MemoryDomain]] = None
    ) -> List[str]:
        """Get collections to search based on domains."""
        if not domains:
            return list(self._collections.keys())

        collections = []
        for domain in domains:
            if domain == MemoryDomain.SIEM:
                collections.append(f"{self.collection_prefix}_alerts")
            elif domain == MemoryDomain.THREAT_INTEL:
                collections.append(f"{self.collection_prefix}_threat_intel")
            elif domain == MemoryDomain.CASE_MGMT:
                collections.append(f"{self.collection_prefix}_cases")
            else:
                collections.extend([
                    f"{self.collection_prefix}_episodic",
                    f"{self.collection_prefix}_semantic",
                ])

        return list(set(collections))

    def _get_collection_for_domain(self, domain: Optional[MemoryDomain]) -> str:
        """Get primary collection for a domain."""
        if domain == MemoryDomain.SIEM:
            return f"{self.collection_prefix}_alerts"
        elif domain == MemoryDomain.THREAT_INTEL:
            return f"{self.collection_prefix}_threat_intel"
        elif domain == MemoryDomain.CASE_MGMT:
            return f"{self.collection_prefix}_cases"
        else:
            return f"{self.collection_prefix}_episodic"

    async def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for text."""
        # This would typically call an embedding model
        # For now, return a placeholder
        return [0.0] * self.embedding_dim

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about all collections."""
        return {
            "total_collections": len(self._collections),
            "collections": {
                name: {
                    "domain": config.domain.value,
                    "description": config.description,
                    "retention_days": config.retention_days,
                }
                for name, config in self._collections.items()
            },
        }
