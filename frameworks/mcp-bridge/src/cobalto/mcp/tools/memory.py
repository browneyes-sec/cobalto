"""
Memory MCP Tools - Tools for interacting with Data Mesh memory system.
"""

from typing import Any, Dict, List, Optional
from cobalto.mcp.registry.tools import mcp_tool
from cobalto.mcp.registry.resources import mcp_resource


@mcp_tool(
    name="memory_store",
    description="Store a memory in the data mesh",
    input_schema={
        "type": "object",
        "properties": {
            "content": {"type": "string", "description": "Memory content to store"},
            "memory_type": {
                "type": "string",
                "enum": ["episodic", "semantic", "procedural", "reflective"],
                "description": "Type of memory"
            },
            "domain": {
                "type": "string",
                "enum": ["siem", "threat_intel", "case_mgmt", "response", "hunt", "agent"],
                "description": "Memory domain"
            },
            "agent_id": {"type": "string", "description": "Agent ID"},
            "importance": {"type": "number", "description": "Importance (0-1)", "default": 0.5},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags"},
        },
        "required": ["content", "memory_type", "domain"],
    },
    tags=["memory", "datamesh"],
)
async def memory_store(
    content: str,
    memory_type: str,
    domain: str,
    agent_id: Optional[str] = None,
    importance: float = 0.5,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Store memory in data mesh."""
    from cobalto.agent.datamesh import DataMeshMemory, MemoryEntry, MemoryMetadata, MemoryDomain, MemoryPriority
    from cobalto.core.config import get_settings
    import uuid

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    entry = MemoryEntry(
        id=str(uuid.uuid4()),
        content=content,
        memory_type=memory_type,
        metadata=MemoryMetadata(
            domain=MemoryDomain(domain),
            agent_id=agent_id,
            tags=tags or [],
            priority=MemoryPriority.MEDIUM,
        ),
        importance=importance,
    )

    success = await memory.store(entry)

    return {
        "success": success,
        "memory_id": entry.id,
        "memory_type": memory_type,
        "domain": domain,
    }


@mcp_tool(
    name="memory_search",
    description="Search memories in the data mesh",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "domains": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by domains"
            },
            "memory_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by memory types"
            },
            "agent_id": {"type": "string", "description": "Filter by agent ID"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter by tags"},
            "limit": {"type": "integer", "description": "Max results", "default": 10},
        },
        "required": ["query"],
    },
    tags=["memory", "datamesh", "search"],
)
async def memory_search(
    query: str,
    domains: Optional[List[str]] = None,
    memory_types: Optional[List[str]] = None,
    agent_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    limit: int = 10,
) -> Dict[str, Any]:
    """Search memories in data mesh."""
    from cobalto.agent.datamesh import DataMeshMemory, MemoryDomain
    from cobalto.core.config import get_settings

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    # Convert domain strings to enums
    domain_enums = None
    if domains:
        domain_enums = [MemoryDomain(d) for d in domains]

    # Generate a simple embedding for the query
    # In production, this would use an embedding model
    query_embedding = [0.0] * settings.memory_embedding_dimensions

    results = await memory.search(
        query_embedding=query_embedding,
        domains=domain_enums,
        memory_types=memory_types,
        agent_id=agent_id,
        tags=tags,
        limit=limit,
    )

    return {
        "count": len(results),
        "memories": [
            {
                "id": r.id,
                "content": r.content,
                "memory_type": r.memory_type,
                "domain": r.metadata.domain.value,
                "importance": r.importance,
                "created_at": r.created_at.isoformat(),
            }
            for r in results
        ],
    }


@mcp_tool(
    name="memory_get_recent",
    description="Get recent memories from the data mesh",
    input_schema={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "enum": ["siem", "threat_intel", "case_mgmt", "response", "hunt", "agent"],
                "description": "Filter by domain"
            },
            "agent_id": {"type": "string", "description": "Filter by agent ID"},
            "limit": {"type": "integer", "description": "Max results", "default": 50},
        },
        "required": [],
    },
    tags=["memory", "datamesh", "recent"],
)
async def memory_get_recent(
    domain: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Get recent memories."""
    from cobalto.agent.datamesh import DataMeshMemory, MemoryDomain
    from cobalto.core.config import get_settings

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    domain_enum = MemoryDomain(domain) if domain else None

    results = await memory.get_recent(
        domain=domain_enum,
        agent_id=agent_id,
        limit=limit,
    )

    return {
        "count": len(results),
        "memories": [
            {
                "id": r.id,
                "content": r.content,
                "memory_type": r.memory_type,
                "domain": r.metadata.domain.value,
                "importance": r.importance,
                "created_at": r.created_at.isoformat(),
            }
            for r in results
        ],
    }


@mcp_tool(
    name="memory_consolidate",
    description="Consolidate memories in a domain",
    input_schema={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "enum": ["siem", "threat_intel", "case_mgmt", "response", "hunt", "agent"],
                "description": "Domain to consolidate"
            },
            "max_age_days": {"type": "integer", "description": "Max age in days", "default": 7},
        },
        "required": ["domain"],
    },
    tags=["memory", "datamesh", "consolidation"],
    requires_approval=True,
)
async def memory_consolidate(
    domain: str,
    max_age_days: int = 7,
) -> Dict[str, Any]:
    """Consolidate memories in domain."""
    from cobalto.agent.datamesh import DataMeshMemory, MemoryDomain
    from cobalto.core.config import get_settings

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    domain_enum = MemoryDomain(domain)

    stats = await memory.consolidate(
        domain=domain_enum,
        max_age_days=max_age_days,
    )

    return {
        "success": True,
        "domain": domain,
        "stats": stats,
    }


@mcp_tool(
    name="memory_share",
    description="Share a memory with other agents",
    input_schema={
        "type": "object",
        "properties": {
            "memory_id": {"type": "string", "description": "Memory ID to share"},
            "target_agents": {"type": "array", "items": {"type": "string"}, "description": "Target agent IDs"},
            "permission": {"type": "string", "enum": ["read", "read_write"], "default": "read"},
        },
        "required": ["memory_id", "target_agents"],
    },
    tags=["memory", "datamesh", "sharing"],
)
async def memory_share(
    memory_id: str,
    target_agents: List[str],
    permission: str = "read",
) -> Dict[str, Any]:
    """Share memory with other agents."""
    from cobalto.agent.datamesh import DataMeshMemory
    from cobalto.core.config import get_settings

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    success = await memory.share_memory(
        entry_id=memory_id,
        target_agents=target_agents,
        permission_level=permission,
    )

    return {
        "success": success,
        "memory_id": memory_id,
        "shared_with": target_agents,
        "permission": permission,
    }


@mcp_tool(
    name="memory_get_stats",
    description="Get memory system statistics",
    input_schema={
        "type": "object",
        "properties": {},
        "required": [],
    },
    tags=["memory", "datamesh", "stats"],
)
async def memory_get_stats() -> Dict[str, Any]:
    """Get memory system statistics."""
    from cobalto.agent.datamesh import DataMeshMemory
    from cobalto.core.config import get_settings

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    return memory.get_collection_stats()


@mcp_resource(
    uri="memory://collections",
    name="Memory Collections",
    description="List all memory collections",
    tags=["memory", "datamesh"],
)
async def memory_collections_resource(uri: str) -> Dict[str, Any]:
    """Get memory collections resource."""
    from cobalto.agent.datamesh import DataMeshMemory
    from cobalto.core.config import get_settings

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    return memory.get_collection_stats()


@mcp_resource(
    uri="memory://recent/{domain}",
    name="Recent Domain Memories",
    description="Get recent memories for a specific domain",
    is_template=True,
    uri_template="memory://recent/{domain}",
    tags=["memory", "datamesh", "domain"],
)
async def memory_domain_recent_resource(uri: str) -> Dict[str, Any]:
    """Get recent memories for domain."""
    # Extract domain from URI
    parts = uri.split("/")
    domain = parts[-1] if len(parts) > 1 else "agent"

    from cobalto.agent.datamesh import DataMeshMemory, MemoryDomain
    from cobalto.core.config import get_settings

    settings = get_settings()

    memory = DataMeshMemory(
        qdrant_url=settings.qdrant_url,
        collection_prefix=settings.qdrant_collection_prefix,
    )

    try:
        domain_enum = MemoryDomain(domain)
    except ValueError:
        domain_enum = MemoryDomain.AGENT

    results = await memory.get_recent(domain=domain_enum, limit=20)

    return {
        "domain": domain,
        "count": len(results),
        "memories": [
            {
                "id": r.id,
                "content": r.content[:200],  # Truncate for resource
                "memory_type": r.memory_type,
                "created_at": r.created_at.isoformat(),
            }
            for r in results
        ],
    }
