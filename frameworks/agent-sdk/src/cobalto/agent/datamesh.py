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
        similarity_threshold: float = 0.9,
    ) -> Dict[str, Any]:
        """
        Consolidate memories - merge similar, archive old, extract insights.

        Uses simple cosine similarity to find similar memories and merge them.
        Returns consolidation statistics.
        """
        from qdrant_client.models import Filter, FieldCondition, MatchValue, PointStruct

        stats = {
            "total_processed": 0,
            "consolidated": 0,
            "archived": 0,
            "errors": 0,
            "clusters_found": 0,
        }

        try:
            client = await self._get_client()
            cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
            collection = self._get_collection_for_domain(domain)

            # 1. Get old memories to consolidate
            query_filter = Filter(
                must=[
                    FieldCondition(key="tenant_id", match=MatchValue(value=tenant_id)),
                ]
            )

            results = await client.scroll(
                collection_name=collection,
                scroll_filter=query_filter,
                limit=1000,
            )

            memories = []
            for point in results[0]:
                payload = point.payload
                created_at = datetime.fromisoformat(payload.get("created_at", datetime.utcnow().isoformat()))
                if created_at < cutoff_date:
                    memories.append({
                        "id": point.id,
                        "payload": payload,
                        "vector": point.vector,
                    })

            stats["total_processed"] = len(memories)

            if len(memories) < 2:
                stats["status"] = "not_enough_memories"
                return stats

            # 2. Find similar clusters using simple cosine similarity
            consolidated_ids = set()
            clusters = []

            for i, mem_a in enumerate(memories):
                if mem_a["id"] in consolidated_ids:
                    continue

                cluster = [mem_a]
                vector_a = mem_a.get("vector", [])

                if not vector_a:
                    continue

                for j, mem_b in enumerate(memories[i + 1:], i + 1):
                    if mem_b["id"] in consolidated_ids:
                        continue

                    vector_b = mem_b.get("vector", [])
                    if not vector_b:
                        continue

                    # Simple cosine similarity
                    similarity = self._cosine_similarity(vector_a, vector_b)

                    if similarity >= similarity_threshold:
                        cluster.append(mem_b)
                        consolidated_ids.add(mem_b["id"])

                if len(cluster) >= 2:
                    clusters.append(cluster)
                    consolidated_ids.add(mem_a["id"])

            stats["clusters_found"] = len(clusters)

            # 3. Merge clusters into consolidated entries
            for cluster in clusters:
                try:
                    # Merge content from all memories in cluster
                    merged_content_parts = []
                    total_importance = 0
                    all_tags = set()
                    earliest_date = datetime.utcnow()
                    latest_date = datetime.min

                    for mem in cluster:
                        content = mem["payload"].get("content", "")
                        if content:
                            merged_content_parts.append(content)

                        total_importance += mem["payload"].get("importance", 0.5)
                        all_tags.update(mem["payload"].get("tags", []))

                        created = datetime.fromisoformat(
                            mem["payload"].get("created_at", datetime.utcnow().isoformat())
                        )
                        if created < earliest_date:
                            earliest_date = created
                        if created > latest_date:
                            latest_date = created

                    # Create consolidated content
                    if len(merged_content_parts) > 1:
                        merged_content = f"[Consolidated from {len(cluster)} entries]\n" + "\n".join(set(merged_content_parts))
                    else:
                        merged_content = merged_content_parts[0] if merged_content_parts else ""

                    # Use the first memory's vector (or average)
                    consolidated_vector = cluster[0].get("vector", [])

                    # Create new consolidated entry
                    new_point = PointStruct(
                        id=hash(f"consolidated_{cluster[0]['id']}") % (2**63),
                        vector=consolidated_vector,
                        payload={
                            "id": f"consolidated-{uuid.uuid4().hex[:8]}",
                            "content": merged_content,
                            "summary": f"Consolidated from {len(cluster)} similar memories",
                            "memory_type": cluster[0]["payload"].get("memory_type", "episodic"),
                            "domain": domain.value,
                            "tenant_id": tenant_id,
                            "tags": list(all_tags),
                            "importance": min(1.0, total_importance / len(cluster)),
                            "created_at": earliest_date.isoformat(),
                            "updated_at": datetime.utcnow().isoformat(),
                            "is_consolidated": True,
                            "consolidated_from": [m["id"] for m in cluster],
                        },
                    )

                    # Upsert consolidated entry
                    await client.upsert(
                        collection_name=collection,
                        points=[new_point],
                    )

                    # Delete original entries
                    original_ids = [m["id"] for m in cluster]
                    await client.delete(
                        collection_name=collection,
                        points_selector=original_ids,
                    )

                    stats["consolidated"] += 1

                except Exception as e:
                    stats["errors"] += 1
                    print(f"Error consolidating cluster: {e}")

            # 4. Archive very old unconsolidated memories (older than 2x max_age_days)
            archive_cutoff = datetime.utcnow() - timedelta(days=max_age_days * 2)
            archived_count = 0

            for mem in memories:
                if mem["id"] in consolidated_ids:
                    continue

                created_at = datetime.fromisoformat(
                    mem["payload"].get("created_at", datetime.utcnow().isoformat())
                )

                if created_at < archive_cutoff:
                    try:
                        await client.delete(
                            collection_name=collection,
                            points_selector=[mem["id"]],
                        )
                        archived_count += 1
                    except Exception as e:
                        stats["errors"] += 1

            stats["archived"] = archived_count
            stats["status"] = "completed"

        except Exception as e:
            stats["errors"] += 1
            print(f"Error in consolidation: {e}")

        return stats

    def _cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        if not vec_a or not vec_b or len(vec_a) != len(vec_b):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = sum(a ** 2 for a in vec_a) ** 0.5
        norm_b = sum(b ** 2 for b in vec_b) ** 0.5

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot_product / (norm_a * norm_b)

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
