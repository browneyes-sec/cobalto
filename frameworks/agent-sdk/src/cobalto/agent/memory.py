"""
Agent memory system for short-term and long-term storage.
Provides conversation history, context persistence, and knowledge retrieval.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import json
import asyncio


class MemoryType(str, Enum):
    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"


class MemoryEntry(BaseModel):
    """A single memory entry."""
    id: str
    content: str
    memory_type: MemoryType
    metadata: Dict[str, Any] = {}
    embedding: Optional[List[float]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    importance: float = 0.5
    access_count: int = 0


class ShortTermMemory:
    """Short-term memory using Redis for conversation context."""

    def __init__(self, redis_url: str, ttl_seconds: int = 3600):
        self.redis_url = redis_url
        self.ttl_seconds = ttl_seconds
        self._redis = None

    async def _get_redis(self):
        """Get or create Redis connection."""
        if self._redis is None:
            import redis.asyncio as redis
            self._redis = redis.from_url(self.redis_url)
        return self._redis

    async def add(self, key: str, entry: MemoryEntry, ttl: Optional[int] = None) -> bool:
        """Add an entry to short-term memory."""
        try:
            r = await self._get_redis()
            data = entry.model_dump_json()
            await r.setex(
                f"stm:{key}:{entry.id}",
                ttl or self.ttl_seconds,
                data,
            )
            # Add to conversation history
            await r.lpush(f"stm:history:{key}", entry.id)
            await r.ltrim(f"stm:history:{key}", 0, 99)  # Keep last 100 entries
            return True
        except Exception as e:
            print(f"Short-term memory add failed: {e}")
            return False

    async def get(self, key: str, entry_id: str) -> Optional[MemoryEntry]:
        """Get an entry from short-term memory."""
        try:
            r = await self._get_redis()
            data = await r.get(f"stm:{key}:{entry_id}")
            if data:
                return MemoryEntry.model_validate_json(data)
            return None
        except Exception as e:
            print(f"Short-term memory get failed: {e}")
            return None

    async def get_history(self, key: str, limit: int = 50) -> List[MemoryEntry]:
        """Get conversation history."""
        try:
            r = await self._get_redis()
            entry_ids = await r.lrange(f"stm:history:{key}", 0, limit - 1)
            entries = []
            for entry_id in entry_ids:
                entry = await self.get(key, entry_id.decode())
                if entry:
                    entries.append(entry)
            return entries
        except Exception as e:
            print(f"Short-term memory history failed: {e}")
            return []

    async def clear(self, key: str) -> bool:
        """Clear short-term memory for a key."""
        try:
            r = await self._get_redis()
            pattern = f"stm:{key}:*"
            keys = await r.keys(pattern)
            if keys:
                await r.delete(*keys)
            await r.delete(f"stm:history:{key}")
            return True
        except Exception as e:
            print(f"Short-term memory clear failed: {e}")
            return False

    async def get_context_window(self, key: str, window_size: int = 10) -> str:
        """Get recent context as a formatted string."""
        history = await self.get_history(key, window_size)
        context_parts = []
        for entry in reversed(history):
            context_parts.append(f"[{entry.timestamp.isoformat()}] {entry.content}")
        return "\n".join(context_parts)


class LongTermMemory:
    """Long-term memory using Qdrant for semantic search."""

    def __init__(self, qdrant_url: str, collection_name: str = "agent_memory"):
        self.qdrant_url = qdrant_url
        self.collection_name = collection_name
        self._client = None

    async def _get_client(self):
        """Get or create Qdrant client."""
        if self._client is None:
            from qdrant_client import QdrantClient
            self._client = QdrantClient(url=self.qdrant_url)
        return self._client

    async def add(self, entry: MemoryEntry, embedding: List[float]) -> bool:
        """Add an entry to long-term memory."""
        try:
            from qdrant_client.models import PointStruct
            client = await self._get_client()
            point = PointStruct(
                id=hash(entry.id) % (2**63),
                vector=embedding,
                payload={
                    "content": entry.content,
                    "memory_type": entry.memory_type.value,
                    "metadata": entry.metadata,
                    "timestamp": entry.timestamp.isoformat(),
                    "importance": entry.importance,
                },
            )
            await client.upsert(
                collection_name=self.collection_name,
                points=[point],
            )
            return True
        except Exception as e:
            print(f"Long-term memory add failed: {e}")
            return False

    async def search(
        self,
        query_embedding: List[float],
        limit: int = 10,
        memory_type: Optional[MemoryType] = None,
        min_score: float = 0.7,
    ) -> List[MemoryEntry]:
        """Search long-term memory by semantic similarity."""
        try:
            from qdrant_client.models import Filter, FieldCondition, MatchValue
            client = await self._get_client()

            query_filter = None
            if memory_type:
                query_filter = Filter(
                    must=[
                        FieldCondition(
                            key="memory_type",
                            match=MatchValue(value=memory_type.value),
                        )
                    ]
                )

            results = await client.search(
                collection_name=self.collection_name,
                query_vector=query_embedding,
                limit=limit,
                query_filter=query_filter,
                score_threshold=min_score,
            )

            entries = []
            for result in results:
                payload = result.payload
                entries.append(MemoryEntry(
                    id=str(result.id),
                    content=payload["content"],
                    memory_type=MemoryType(payload["memory_type"]),
                    metadata=payload.get("metadata", {}),
                    timestamp=datetime.fromisoformat(payload["timestamp"]),
                    importance=payload.get("importance", 0.5),
                ))
            return entries
        except Exception as e:
            print(f"Long-term memory search failed: {e}")
            return []

    async def get(self, entry_id: str) -> Optional[MemoryEntry]:
        """Get a specific entry from long-term memory."""
        try:
            client = await self._get_client()
            results = await client.retrieve(
                collection_name=self.collection_name,
                ids=[hash(entry_id) % (2**63)],
            )
            if results:
                payload = results[0].payload
                return MemoryEntry(
                    id=str(results[0].id),
                    content=payload["content"],
                    memory_type=MemoryType(payload["memory_type"]),
                    metadata=payload.get("metadata", {}),
                    timestamp=datetime.fromisoformat(payload["timestamp"]),
                    importance=payload.get("importance", 0.5),
                )
            return None
        except Exception as e:
            print(f"Long-term memory get failed: {e}")
            return None

    async def delete(self, entry_id: str) -> bool:
        """Delete an entry from long-term memory."""
        try:
            client = await self._get_client()
            await client.delete(
                collection_name=self.collection_name,
                points_selector=[hash(entry_id) % (2**63)],
            )
            return True
        except Exception as e:
            print(f"Long-term memory delete failed: {e}")
            return False


class AgentMemory:
    """Unified memory interface combining short-term and long-term storage."""

    def __init__(
        self,
        agent_id: str,
        redis_url: str,
        qdrant_url: str,
        collection_prefix: str = "cobalto",
    ):
        self.agent_id = agent_id
        self.short_term = ShortTermMemory(redis_url)
        self.long_term = LongTermMemory(
            qdrant_url,
            collection_name=f"{collection_prefix}_memory_{agent_id}",
        )

    async def remember(
        self,
        content: str,
        memory_type: MemoryType = MemoryType.SHORT_TERM,
        importance: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None,
        embedding: Optional[List[float]] = None,
    ) -> MemoryEntry:
        """Store a memory."""
        import uuid
        entry = MemoryEntry(
            id=str(uuid.uuid4()),
            content=content,
            memory_type=memory_type,
            metadata=metadata or {},
            importance=importance,
        )

        if memory_type == MemoryType.SHORT_TERM:
            await self.short_term.add(self.agent_id, entry)
        elif memory_type == MemoryType.LONG_TERM and embedding:
            await self.long_term.add(entry, embedding)

        return entry

    async def recall(
        self,
        query: Optional[str] = None,
        query_embedding: Optional[List[float]] = None,
        memory_type: Optional[MemoryType] = None,
        limit: int = 10,
    ) -> List[MemoryEntry]:
        """Recall memories."""
        if query_embedding:
            return await self.long_term.search(query_embedding, limit, memory_type)
        elif query:
            # For short-term, get recent history
            return await self.short_term.get_history(self.agent_id, limit)
        return []

    async def get_context(self, window_size: int = 10) -> str:
        """Get recent context for the agent."""
        return await self.short_term.get_context_window(self.agent_id, window_size)

    async def clear_short_term(self) -> bool:
        """Clear short-term memory."""
        return await self.short_term.clear(self.agent_id)

    async def forget(self, entry_id: str) -> bool:
        """Forget a specific memory."""
        return await self.long_term.delete(entry_id)