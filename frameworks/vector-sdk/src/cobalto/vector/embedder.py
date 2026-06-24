"""
Text embedding models for vector search.
Supports multiple embedding providers and local models.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from enum import Enum
import asyncio
import httpx
from ..core.logging import get_logger
from ..core.metrics import record_external_request

logger = get_logger(__name__)


class EmbeddingModel(str, Enum):
    OPENAI_ADA = "text-embedding-3-small"
    OPENAI_LARGE = "text-embedding-3-large"
    SENTENCE_TRANSFORMERS = "all-MiniLM-L6-v2"
    SENTENCE_TRANSFORMERS_LARGE = "all-mpnet-base-v2"
    JINA = "jina-embeddings-v2-base-en"


class EmbeddingConfig(BaseModel):
    """Configuration for embedding generation."""
    model: EmbeddingModel = EmbeddingModel.OPENAI_ADA
    api_key: Optional[str] = None
    dimensions: int = 1536
    batch_size: int = 100
    max_retries: int = 3
    timeout: float = 30.0


class Embedder:
    """Generates text embeddings from various providers."""

    def __init__(self, config: Optional[EmbeddingConfig] = None):
        self.config = config or EmbeddingConfig()
        self._model = None

    async def embed(self, text: str) -> List[float]:
        """Generate embedding for a single text."""
        results = await self.embed_batch([text])
        return results[0]

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        if self.config.model in (
            EmbeddingModel.OPENAI_ADA,
            EmbeddingModel.OPENAI_LARGE,
        ):
            return await self._embed_openai(texts)
        elif self.config.model in (
            EmbeddingModel.SENTENCE_TRANSFORMERS,
            EmbeddingModel.SENTENCE_TRANSFORMERS_LARGE,
        ):
            return await self._embed_sentence_transformers(texts)
        elif self.config.model == EmbeddingModel.JINA:
            return await self._embed_jina(texts)
        else:
            raise ValueError(f"Unsupported embedding model: {self.config.model}")

    async def _embed_openai(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using OpenAI API."""
        if not self.config.api_key:
            raise ValueError("OpenAI API key required")

        client = httpx.AsyncClient(timeout=self.config.timeout)
        start_time = __import__("time").time()

        try:
            # Process in batches
            all_embeddings = []
            for i in range(0, len(texts), self.config.batch_size):
                batch = texts[i : i + self.config.batch_size]

                response = await client.post(
                    "https://api.openai.com/v1/embeddings",
                    headers={
                        "Authorization": f"Bearer {self.config.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.config.model.value,
                        "input": batch,
                        "dimensions": self.config.dimensions,
                    },
                )

                duration = __import__("time").time() - start_time

                if response.status_code == 200:
                    data = response.json()
                    embeddings = [item["embedding"] for item in data["data"]]
                    all_embeddings.extend(embeddings)
                    record_external_request(
                        "embedder",
                        "openai",
                        "/v1/embeddings",
                        "200",
                        duration,
                    )
                else:
                    record_external_request(
                        "embedder",
                        "openai",
                        "/v1/embeddings",
                        str(response.status_code),
                        duration,
                    )
                    raise Exception(f"OpenAI API error: {response.status_code}")

            return all_embeddings

        finally:
            await client.aclose()

    async def _embed_sentence_transformers(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using sentence-transformers."""
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np

            if self._model is None:
                model_name = "all-MiniLM-L6-v2"
                if self.config.model == EmbeddingModel.SENTENCE_TRANSFORMERS_LARGE:
                    model_name = "all-mpnet-base-v2"
                self._model = SentenceTransformer(model_name)

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            embeddings = await loop.run_in_executor(
                None,
                lambda: self._model.encode(texts, show_progress_bar=False),
            )

            return embeddings.tolist()

        except ImportError:
            raise ImportError(
                "sentence-transformers package required. "
                "Install with: pip install sentence-transformers"
            )

    async def _embed_jina(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using Jina API."""
        if not self.config.api_key:
            raise ValueError("Jina API key required")

        client = httpx.AsyncClient(timeout=self.config.timeout)
        start_time = __import__("time").time()

        try:
            all_embeddings = []
            for i in range(0, len(texts), self.config.batch_size):
                batch = texts[i : i + self.config.batch_size]

                response = await client.post(
                    "https://api.jina.ai/v1/embeddings",
                    headers={
                        "Authorization": f"Bearer {self.config.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.config.model.value,
                        "input": batch,
                    },
                )

                duration = __import__("time").time() - start_time

                if response.status_code == 200:
                    data = response.json()
                    embeddings = [item["embedding"] for item in data["data"]]
                    all_embeddings.extend(embeddings)
                    record_external_request(
                        "embedder",
                        "jina",
                        "/v1/embeddings",
                        "200",
                        duration,
                    )
                else:
                    record_external_request(
                        "embedder",
                        "jina",
                        "/v1/embeddings",
                        str(response.status_code),
                        duration,
                    )
                    raise Exception(f"Jina API error: {response.status_code}")

            return all_embeddings

        finally:
            await client.aclose()

    def get_dimensions(self) -> int:
        """Get the embedding dimensions for the current model."""
        dimension_map = {
            EmbeddingModel.OPENAI_ADA: 1536,
            EmbeddingModel.OPENAI_LARGE: 3072,
            EmbeddingModel.SENTENCE_TRANSFORMERS: 384,
            EmbeddingModel.SENTENCE_TRANSFORMERS_LARGE: 768,
            EmbeddingModel.JINA: 768,
        }
        return dimension_map.get(self.config.model, 1536)