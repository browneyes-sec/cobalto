"""
Layer 5: Memory Context

What happened before in this incident?
prior_agent_runs[], analyst_annotations[]
(Sliding window + summarization for long cases)
"""

from typing import Any, Dict, List, Optional
import redis.asyncio as redis
import json
import structlog

logger = structlog.get_logger(__name__)

# Sliding window size: keep last N runs in full
MEMORY_WINDOW_SIZE = 5


class MemoryLayer:
    """Loads agent memory with sliding window + summarization."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._redis: Optional[redis.Redis] = None

    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(self.redis_url)
        return self._redis

    async def load(self, incident_id: str) -> Dict[str, Any]:
        """Load memory context with sliding window."""
        logger.info("loading_memory_context", incident_id=incident_id)

        r = await self._get_redis()

        # Get all prior agent runs for this incident
        prior_runs = await self._get_prior_runs(r, incident_id)

        # Get analyst annotations
        annotations = await self._get_annotations(r, incident_id)

        # Get session context
        session_context = await self._get_session_context(r, incident_id)

        # Apply sliding window + summarization
        if len(prior_runs) > MEMORY_WINDOW_SIZE:
            summary = self._summarize_runs(prior_runs[:-MEMORY_WINDOW_SIZE])
            recent = prior_runs[-MEMORY_WINDOW_SIZE:]
            return {
                "summary": summary,
                "recent_runs": recent,
                "total_runs": len(prior_runs),
                "analyst_annotations": annotations,
                "session_context": session_context,
                "window_size": MEMORY_WINDOW_SIZE,
                "has_more": True,
            }

        return {
            "recent_runs": prior_runs,
            "total_runs": len(prior_runs),
            "analyst_annotations": annotations,
            "session_context": session_context,
            "window_size": len(prior_runs),
            "has_more": False,
        }

    async def _get_prior_runs(self, r: redis.Redis, incident_id: str) -> List[Dict]:
        """Get prior agent runs for this incident."""
        key = f"agent_runs:{incident_id}"
        data = await r.lrange(key, 0, -1)
        return [json.loads(d) for d in data]

    async def _get_annotations(self, r: redis.Redis, incident_id: str) -> List[Dict]:
        """Get analyst annotations."""
        key = f"annotations:{incident_id}"
        data = await r.get(key)
        return json.loads(data) if data else []

    async def _get_session_context(self, r: redis.Redis, incident_id: str) -> Dict[str, Any]:
        """Get session context for the incident."""
        key = f"session:{incident_id}"
        data = await r.get(key)
        return json.loads(data) if data else {}

    def _summarize_runs(self, runs: List[Dict]) -> str:
        """Summarize older runs to prevent context overflow."""
        if not runs:
            return ""

        # Group by agent type and status
        agent_summary: Dict[str, Dict[str, int]] = {}
        for run in runs:
            agent = run.get("agent_type", "unknown")
            status = run.get("status", "unknown")
            if agent not in agent_summary:
                agent_summary[agent] = {}
            agent_summary[agent][status] = agent_summary[agent].get(status, 0) + 1

        # Build summary
        parts = []
        for agent, statuses in agent_summary.items():
            status_str = ", ".join([f"{s}: {c}" for s, c in statuses.items()])
            parts.append(f"{agent} ({status_str})")

        return f"Previous runs ({len(runs)}): " + "; ".join(parts)

    async def store_agent_run(
        self,
        incident_id: str,
        agent_type: str,
        status: str,
        output: Dict[str, Any],
    ) -> None:
        """Store an agent run in memory."""
        r = await self._get_redis()

        run_data = {
            "agent_type": agent_type,
            "status": status,
            "output": output,
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        }

        key = f"agent_runs:{incident_id}"
        await r.rpush(key, json.dumps(run_data))

        # Trim to keep only last 20 runs
        await r.ltrim(key, -20, -1)

        logger.info(
            "agent_run_stored",
            incident_id=incident_id,
            agent_type=agent_type,
            status=status,
        )

    async def store_annotation(
        self,
        incident_id: str,
        analyst_id: str,
        annotation: str,
    ) -> None:
        """Store an analyst annotation."""
        r = await self._get_redis()

        key = f"annotations:{incident_id}"
        existing = await r.get(key)
        annotations = json.loads(existing) if existing else []

        annotations.append({
            "analyst_id": analyst_id,
            "annotation": annotation,
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        })

        await r.set(key, json.dumps(annotations))

        logger.info(
            "annotation_stored",
            incident_id=incident_id,
            analyst_id=analyst_id,
        )
