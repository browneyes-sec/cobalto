#!/usr/bin/env python3
"""Seed MITRE ATT&CK techniques into Qdrant for Cobalto SOC/MDR platform."""

import os
import sys
import json
import time
import logging
from typing import Optional
from urllib.parse import urlparse

import requests
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
    PayloadSchemaType,
    TextIndexParams,
    TokenizerType,
)
from openai import OpenAI
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
COLLECTION_NAME = "mitre_attack"
VECTOR_SIZE = 3072
EMBEDDING_MODEL = "text-embedding-3-large"
BATCH_SIZE = 64
MAX_RETRIES = 5
RETRY_DELAY = 2


def get_qdrant_client() -> QdrantClient:
    parsed = urlparse(QDRANT_URL)
    host = parsed.hostname or "localhost"
    port = parsed.port or 6333
    https = parsed.scheme == "https"
    return QdrantClient(host=host, port=port, https=https)


def ensure_collection(client: QdrantClient) -> None:
    collections = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME in collections:
        logger.info("Collection '%s' already exists, recreating", COLLECTION_NAME)
        client.delete_collection(COLLECTION_NAME)
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )
    client.create_payload_index(
        collection_name=COLLECTION_NAME,
        field_name="technique_id",
        field_schema=PayloadSchemaType.KEYWORD,
    )
    client.create_payload_index(
        collection_name=COLLECTION_NAME,
        field_name="technique_name",
        field_schema=TextIndexParams(
            type="text",
            tokenizer=TokenizerType.WORD,
            min_token_len=2,
            max_token_len=15,
            lowercase=True,
        ),
    )
    logger.info("Collection '%s' created with indexes", COLLECTION_NAME)


def download_stix_data() -> dict:
    logger.info("Downloading MITRE ATT&CK STIX2 data from GitHub...")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(MITRE_STIX_URL, timeout=60)
            resp.raise_for_status()
            logger.info("Downloaded %.1f MB", len(resp.content) / (1024 * 1024))
            return resp.json()
        except (requests.RequestException, json.JSONDecodeError) as exc:
            logger.warning("Attempt %d/%d failed: %s", attempt, MAX_RETRIES, exc)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
    raise RuntimeError("Failed to download MITRE ATT&CK data after retries")


def parse_techniques(stix_bundle: dict) -> list[dict]:
    techniques = []
    obj_lookup = {obj["id"]: obj for obj in stix_bundle.get("objects", [])}

    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        external_ids = [
            ref["external_id"]
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ]
        technique_id = next((eid for eid in external_ids if eid.startswith("T")), None)
        if not technique_id:
            continue

        platforms = obj.get("platforms", [])
        kill_chain_phases = []
        for kc in obj.get("kill_chain_phases", []):
            if kc.get("kill_chain_name") == "mitre-attack":
                kill_chain_phases.append(kc.get("phase_name", ""))

        data_sources = []
        for ds in obj.get("x_mitre_data_sources", []):
            if isinstance(ds, str):
                data_sources.append(ds)
            elif isinstance(ds, dict):
                data_sources.append(ds.get("name", str(ds)))

        mitigations = []
        for rel in stix_bundle.get("objects", []):
            if rel.get("type") == "relationship" and rel.get("relationship_type") == "mitigates":
                if rel.get("target_ref") == obj["id"]:
                    source_obj = obj_lookup.get(rel.get("source_ref"))
                    if source_obj:
                        mit_ids = [
                            r["external_id"]
                            for r in source_obj.get("external_references", [])
                            if r.get("source_name") == "mitre-attack"
                        ]
                        mit_name = source_obj.get("name", "")
                        if mit_ids:
                            mitigations.append({"id": mit_ids[0], "name": mit_name})

        description = obj.get("description", "").strip()
        name = obj.get("name", "")

        techniques.append({
            "technique_id": technique_id,
            "technique_name": name,
            "description": description,
            "platforms": platforms,
            "kill_chain_phases": kill_chain_phases,
            "data_sources": data_sources,
            "mitigations": mitigations,
            "stix_id": obj.get("id", ""),
            "url": next(
                (r["url"] for r in obj.get("external_references", []) if "url" in r),
                "",
            ),
        })

    logger.info("Parsed %d techniques from STIX bundle", len(techniques))
    return techniques


def embed_texts(client: OpenAI, texts: list[str]) -> list[list[float]]:
    all_embeddings = []
    for i in tqdm(range(0, len(texts), BATCH_SIZE), desc="Embedding", unit="batch"):
        batch = texts[i : i + BATCH_SIZE]
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = client.embeddings.create(model=EMBEDDING_MODEL, input=batch)
                all_embeddings.extend([d.embedding for d in resp.data])
                break
            except Exception as exc:
                logger.warning("Embedding batch %d attempt %d failed: %s", i // BATCH_SIZE, attempt, exc)
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
                else:
                    raise
    return all_embeddings


def seed_qdrant(client: QdrantClient, techniques: list[dict], embeddings: list[list[float]]) -> int:
    points = []
    for tech, emb in zip(techniques, embeddings):
        point = PointStruct(
            id=hash(tech["technique_id"]) % (2**63),
            vector=emb,
            payload={
                "technique_id": tech["technique_id"],
                "technique_name": tech["technique_name"],
                "description": tech["description"],
                "platforms": tech["platforms"],
                "kill_chain_phases": tech["kill_chain_phases"],
                "data_sources": tech["data_sources"],
                "mitigations": tech["mitigations"],
                "stix_id": tech["stix_id"],
                "url": tech["url"],
            },
        )
        points.append(point)

    upserted = 0
    for i in tqdm(range(0, len(points), BATCH_SIZE), desc="Upserting", unit="batch"):
        batch = points[i : i + BATCH_SIZE]
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                client.upsert(collection_name=COLLECTION_NAME, points=batch)
                upserted += len(batch)
                break
            except Exception as exc:
                logger.warning("Upsert batch %d attempt %d failed: %s", i // BATCH_SIZE, attempt, exc)
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
                else:
                    raise

    return upserted


def main():
    if not OPENAI_API_KEY:
        logger.error("OPENAI_API_KEY environment variable is not set")
        sys.exit(1)

    qdrant_client = get_qdrant_client()
    openai_client = OpenAI(api_key=OPENAI_API_KEY)

    stix_data = download_stix_data()
    techniques = parse_techniques(stix_data)
    if not techniques:
        logger.error("No techniques found in STIX bundle")
        sys.exit(1)

    logger.info("Embedding %d technique descriptions...", len(techniques))
    texts = [t["description"] or t["technique_name"] for t in techniques]
    embeddings = embed_texts(openai_client, texts)

    logger.info("Ensuring Qdrant collection exists...")
    ensure_collection(qdrant_client)

    count = seed_qdrant(qdrant_client, techniques, embeddings)
    logger.info("Successfully seeded %d MITRE ATT&CK techniques into '%s'", count, COLLECTION_NAME)


if __name__ == "__main__":
    main()
