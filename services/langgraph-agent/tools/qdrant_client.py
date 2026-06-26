from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
)
import os
import uuid
from typing import Optional


class QdrantVectorClient:
    def __init__(self):
        self.url = os.getenv("QDRANT_URL", "http://localhost:6333")
        self.api_key = os.getenv("QDRANT_API_KEY", None)
        self.collection = os.getenv("QDRANT_COLLECTION", "mitre_attack")
        self.vector_size = int(os.getenv("QDRANT_VECTOR_SIZE", "1536"))
        self.client = QdrantClient(url=self.url, api_key=self.api_key)

    def ensure_collection(self):
        collections = [c.name for c in self.client.get_collections().collections]
        if self.collection not in collections:
            self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(
                    size=self.vector_size,
                    distance=Distance.COSINE,
                ),
            )

    def ingest_documents(self, documents: list[dict]) -> list[str]:
        points = []
        ids = []
        for doc in documents:
            point_id = str(uuid.uuid4())
            ids.append(point_id)
            points.append(
                PointStruct(
                    id=point_id,
                    vector=doc.get("vector", [0.0] * self.vector_size),
                    payload={
                        "technique_id": doc.get("technique_id", ""),
                        "technique_name": doc.get("technique_name", ""),
                        "description": doc.get("description", ""),
                        "text": doc.get("text", ""),
                        "source": doc.get("source", "mitre_attack"),
                    },
                )
            )
        self.client.upsert(collection_name=self.collection, points=points)
        return ids

    def similarity_search_with_score(
        self,
        query_vector: list[float],
        limit: int = 5,
        technique_id: Optional[str] = None,
    ) -> list[dict]:
        query_filter = None
        if technique_id:
            query_filter = Filter(
                must=[
                    FieldCondition(
                        key="technique_id",
                        match=MatchValue(value=technique_id),
                    )
                ]
            )

        results = self.client.search(
            collection_name=self.collection,
            query_vector=query_vector,
            limit=limit,
            query_filter=query_filter,
        )
        return [
            {
                "id": r.id,
                "score": r.score,
                "payload": r.payload,
            }
            for r in results
        ]

    def get_collection_info(self) -> dict:
        info = self.client.get_collection(self.collection)
        return {
            "name": info.name,
            "vectors_count": info.vectors_count,
            "points_count": info.points_count,
            "status": info.status,
        }

    def delete_collection(self):
        self.client.delete_collection(collection_name=self.collection)
