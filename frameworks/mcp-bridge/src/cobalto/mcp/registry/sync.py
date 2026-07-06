"""
MCP → UnifiedToolRegistry Sync.

Migrates existing ``@mcp_tool``-decorated functions from the MCP bridge's
legacy ``ToolRegistry`` into the single-source-of-truth
``UnifiedToolRegistry`` from agent-sdk.

Call ``sync_mcp_tools_to_unified()`` at application startup to populate the
unified registry with all existing MCP tool implementations. After sync,
the ``UnifiedMCPAdapter`` (or the MCPServer with ``unified_tool_registry=``)
will serve the exact same tool set.

When both registries contain the same tools, you can eventually remove the
legacy ``ToolRegistry`` and all ``@mcp_tool`` decorators, registering directly
on ``UnifiedToolRegistry`` instead.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Dict, List, Optional

from cobalto.agent.tool_registry import (
    AsyncToolWrapper,
    ToolDefinition,
    ToolRiskLevel,
    UnifiedToolRegistry,
    get_tool_registry,
)

from cobalto.mcp.registry.tools import ToolRegistry, get_tool_registry as get_legacy_registry

logger = logging.getLogger(__name__)


def sync_mcp_tools_to_unified(
    legacy_registry: Optional[ToolRegistry] = None,
    unified_registry: Optional[UnifiedToolRegistry] = None,
    tag: str = "mcp",
) -> int:
    """Copy all tools from the legacy MCP ``ToolRegistry`` into the
    ``UnifiedToolRegistry``.

    Each tool is registered with an ``"mcp"`` tag (plus any existing tags),
    so the ``UnifiedMCPAdapter`` can discover them.

    Args:
        legacy_registry: Legacy MCP ToolRegistry to read from.
                         Defaults to the global singleton.
        unified_registry: UnifiedToolRegistry to write into.
                          Defaults to the global singleton.
        tag: Tag to apply so the adapter can filter for MCP tools.

    Returns:
        Number of tools migrated.
    """
    legacy = legacy_registry or get_legacy_registry()
    unified = unified_registry or get_tool_registry()

    count = 0
    for name in legacy.list_tool_names():
        # Skip if already registered in the unified registry
        if unified.has_tool(name):
            continue

        legacy_defn = legacy.get_tool(name)
        if legacy_defn is None:
            continue

        # Convert tags: ensure the MCP tag is present
        tags: List[str] = list(legacy_defn.tags or [])
        if tag not in tags:
            tags.append(tag)

        # Map risk level: legacy has requires_approval bool, not a risk enum
        # We map: requires_approval=True → HIGH, else LOW
        risk = ToolRiskLevel.HIGH if legacy_defn.requires_approval else ToolRiskLevel.LOW

        # Build a ToolDefinition
        definition = ToolDefinition(
            name=legacy_defn.name,
            description=legacy_defn.description,
            parameters=legacy_defn.input_schema,
            risk_level=risk,
            requires_approval=legacy_defn.requires_approval,
            timeout_seconds=getattr(legacy_defn, "timeout_seconds", 30),
            tags=tags,
        )

        # Wrap the original function as an executor
        executor = AsyncToolWrapper(legacy_defn.func)

        unified.register(definition=definition, executor=executor)
        count += 1
        logger.debug("Migrated MCP tool '%s' to UnifiedToolRegistry", name)

    if count:
        logger.info("Migrated %d MCP tools to UnifiedToolRegistry", count)
    else:
        logger.info("No MCP tools needed migration (all already present)")

    return count


def sync_all_mcp_tools(
    legacy_registry: Optional[ToolRegistry] = None,
    unified_registry: Optional[UnifiedToolRegistry] = None,
) -> Dict[str, int]:
    """Sync all known MCP tool modules from the legacy registry.

    Groups the result by the first tag (as a proxy for the tool domain).

    Returns:
        Dict mapping domain → count of tools migrated.
    """
    legacy = legacy_registry or get_legacy_registry()
    unified = unified_registry or get_tool_registry()

    domain_counts: Dict[str, int] = {}

    for name in legacy.list_tool_names():
        if unified.has_tool(name):
            continue

        legacy_defn = legacy.get_tool(name)
        if legacy_defn is None:
            continue

        tags = list(legacy_defn.tags or [])
        domain = tags[0] if tags else "unknown"

        risk = ToolRiskLevel.HIGH if legacy_defn.requires_approval else ToolRiskLevel.LOW

        if "mcp" not in tags:
            tags.append("mcp")

        definition = ToolDefinition(
            name=legacy_defn.name,
            description=legacy_defn.description,
            parameters=legacy_defn.input_schema,
            risk_level=risk,
            requires_approval=legacy_defn.requires_approval,
            timeout_seconds=getattr(legacy_defn, "timeout_seconds", 30),
            tags=tags,
        )

        executor = AsyncToolWrapper(legacy_defn.func)
        unified.register(definition=definition, executor=executor)

        domain_counts[domain] = domain_counts.get(domain, 0) + 1

    logger.info(
        "sync_all_mcp_tools: migrated %s",
        dict(domain_counts),
    )
    return domain_counts
