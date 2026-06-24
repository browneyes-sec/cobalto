"""
Vector retriever for semantic search.
Provides hybrid search with vector similarity and keyword matching.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from .embedder import Embedder, EmbeddingConfig
from ..core.logging import get_logger

logger = get_logger(__name__)


class SearchMode(str, Enum):
    VECTOR = "vector"
    KEYWORD = "keyword"
    HYBRID = "hybrid"


class RetrievalConfig(BaseModel):
    """Configuration for retrieval."""
    mode: SearchMode = SearchMode.HYBRID
    top_k: int = 10
    min_score: float = 0.5
    vector_weight: float = 0.7
    keyword_weight: float = 0.3
    collection_prefix: str = "cobalto"


class SearchResult(BaseModel):
    """A single search result."""
    id: str
    score: float
    content: str
    metadata: Dict[str, Any] = {}
    collection: str = ""
    vector_score: float = 0.0
    keyword_score: float = 0.0

    @property
    def combined_score(self) -> float:
        """Get the combined score."""
        return self.score


class Retriever:
    """Retriever for semantic search across collections."""

    def __init__(
        self,
        qdrant_url: str,
        embedder: Optional[Embedder] = None,
        config: Optional[RetrievalConfig] = None,
    ):
        self.qdrant_url = qdrant_url
        self.embedder = embedder or Embedder()
        self.config = config or RetrievalConfig()
        self._client = None

    async def _get_client(self):
        """Get or create Qdrant client."""
        if self._client is None:
            from qdrant_client import QdrantClient
            self._client = QdrantClient(url=self.qdrant_url)
        return self._client

    async def search(
        self,
        query: str,
        collection: Optional[str] = None,
        top_k: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """Search for similar documents."""
        k = top_k or self.config.top_k

        # Generate query embedding
        query_embedding = await self.embedder.embed(query)

        client = await self._get_client()

        # Determine collections to search
        collections = await self._get_collections(collection)

        all_results = []

        for coll_name in collections:
            try:
                # Vector search
                vector_results = client.search(
                    collection_name=coll_name,
                    query_vector=query_embedding,
                    limit=k,
                    query_filter=self._build_filter(filters),
                )

                for result in vector_results:
                    payload = result.payload
                    all_results.append(SearchResult(
                        id=str(result.id),
                        score=result.score,
                        content=payload.get("content", ""),
                        metadata=payload.get("metadata", {}),
                        collection=coll_name,
                        vector_score=result.score,
                    ))

            except Exception as e:
                logger.error(
                    "collection_search_failed",
                    collection=coll_name,
                    error=str(e),
                )

        # Sort by score and take top_k
        all_results.sort(key=lambda x: x.score, reverse=True)
        return all_results[:k]

    async def search_with_rerank(
        self,
        query: str,
        collection: Optional[str] = None,
        top_k: Optional[int] = None,
        rerank_top_n: int = 20,
    ) -> List[SearchResult]:
        """Search with reranking."""
        # First, get more results than needed
        initial_results = await self.search(
            query,
            collection,
            top_k=rerank_top_n,
        )

        # Rerank based on content relevance
        reranked = []
        query_lower = query.lower()

        for result in initial_results:
            content_lower = result.content.lower()
            # Simple reranking based on keyword overlap
            query_words = set(query_lower.split())
            content_words = set(content_lower.split())
            overlap = len(query_words & content_words)
            rerank_score = result.score + (overlap * 0.1)

            reranked.append(SearchResult(
                id=result.id,
                score=rerank_score,
                content=result.content,
                metadata=result.metadata,
                collection=result.collection,
                vector_score=result.vector_score,
                keyword_score=overlap / len(query_words) if query_words else 0,
            ))

        reranked.sort(key=lambda x: x.score, reverse=True)
        return reranked[: (top_k or self.config.top_k)]

    async def get_context(
        self,
        query: str,
        collection: Optional[str] = None,
        max_tokens: int = 2000,
    ) -> str:
        """Get relevant context for a query."""
        results = await self.search(query, collection, top_k=5)

        context_parts = []
        current_tokens = 0

        for result in results:
            # Rough token estimate
            tokens = len(result.content.split())
            if current_tokens + tokens > max_tokens:
                break

            context_parts.append(f"[Source: {result.collection}] {result.content}")
            current_tokens += tokens

        return "\n\n".join(context_parts)

    async def _get_collections(self, specific: Optional[str] = None) -> List[str]:
        """Get collections to search."""
        if specific:
            return [f"{self.config.collection_prefix}_{specific}"]

        client = await self._get_client()
        try:
            collections = client.get_collections()
            return [
                c.name
                for c in collections.collections
                if c.name.startswith(self.config.collection_prefix)
            ]
        except Exception as e:
            logger.error("get_collections_failed", error=str(e))
            return []

    def _build_filter(self, filters: Optional[Dict[str, Any]] = None):
        """Build Qdrant filter from dict."""
        if not filters:
            return None

        from qdrant_client.models import Filter, FieldCondition, MatchValue

        conditions = []
        for key, value in filters.items():
            conditions.append(
                FieldCondition(
                    key=f"metadata.{key}",
                    match=MatchValue(value=value),
                )
            )

        return Filter(must=conditions) if conditions else None