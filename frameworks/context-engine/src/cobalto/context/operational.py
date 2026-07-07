"""
Layer 2: Operational Context

What is the current state?
normalized_event, prior_alerts_72h, open_cases
"""

from typing import Any, Dict, List, Optional
import redis.asyncio as redis
import json
import structlog

logger = structlog.get_logger(__name__)


class OperationalLayer:
    """Loads operational state for the incident."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._redis: Optional[redis.Redis] = None

    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(self.redis_url)
        return self._redis

    async def load(self, incident_id: str) -> Dict[str, Any]:
        """Load operational context."""
        r = await self._get_redis()

        # Get prior alerts from last 72h
        prior_alerts = await self._get_prior_alerts(r, incident_id)

        # Get open cases
        open_cases = await self._get_open_cases(r, incident_id)

        # Get related incidents
        related_incidents = await self._get_related_incidents(r, incident_id)

        # Calculate alert velocity
        alert_velocity = self._calculate_alert_velocity(prior_alerts)

        return {
            "incident_id": incident_id,
            "prior_alerts_72h": prior_alerts,
            "open_cases": open_cases,
            "related_incidents": related_incidents,
            "alert_count_24h": len([a for a in prior_alerts if a.get("hours_ago", 0) <= 24]),
            "alert_count_72h": len(prior_alerts),
            "alert_velocity": alert_velocity,
            "related_indicators": self._extract_related_indicators(prior_alerts),
            "first_seen": self._get_first_seen(prior_alerts),
            "last_seen": self._get_last_seen(prior_alerts),
        }

    async def _get_prior_alerts(self, r: redis.Redis, incident_id: str) -> List[Dict]:
        """Get prior alerts from last 72h with same indicators."""
        key = f"alerts:prior:{incident_id}"
        data = await r.get(key)
        if data:
            return json.loads(data)

        # Fallback: return empty list
        return []

    async def _get_open_cases(self, r: redis.Redis, incident_id: str) -> List[Dict]:
        """Get open cases related to this incident."""
        key = f"cases:open:{incident_id}"
        data = await r.get(key)
        if data:
            return json.loads(data)
        return []

    async def _get_related_incidents(self, r: redis.Redis, incident_id: str) -> List[Dict]:
        """Get related incidents."""
        key = f"incidents:related:{incident_id}"
        data = await r.get(key)
        if data:
            return json.loads(data)
        return []

    def _calculate_alert_velocity(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Calculate alert velocity metrics."""
        if not alerts:
            return {
                "alerts_per_hour": 0,
                "trend": "stable",
                "burst_detected": False,
            }

        # Group by hour
        hourly_counts: Dict[str, int] = {}
        for alert in alerts:
            timestamp = alert.get("timestamp", "")
            if timestamp:
                hour_key = timestamp[:13]  # YYYY-MM-DDTHH
                hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1

        if not hourly_counts:
            return {
                "alerts_per_hour": 0,
                "trend": "stable",
                "burst_detected": False,
            }

        # Calculate average and detect bursts
        counts = list(hourly_counts.values())
        avg = sum(counts) / len(counts) if counts else 0
        max_count = max(counts) if counts else 0
        burst_detected = max_count > avg * 2 if avg > 0 else False

        # Determine trend
        if len(counts) >= 2:
            recent = counts[-1]
            previous = counts[-2]
            if recent > previous * 1.5:
                trend = "increasing"
            elif recent < previous * 0.5:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "stable"

        return {
            "alerts_per_hour": round(avg, 2),
            "trend": trend,
            "burst_detected": burst_detected,
            "peak_hour": max(hourly_counts, key=hourly_counts.get) if hourly_counts else None,
        }

    def _extract_related_indicators(self, alerts: List[Dict]) -> List[str]:
        """Extract related indicators from prior alerts."""
        indicators = set()
        for alert in alerts:
            for field in ["source_ip", "destination_ip", "user_name", "host_name"]:
                if alert.get(field):
                    indicators.add(alert[field])
        return list(indicators)

    def _get_first_seen(self, alerts: List[Dict]) -> Optional[str]:
        """Get first seen timestamp from alerts."""
        if not alerts:
            return None
        timestamps = [a.get("timestamp") for a in alerts if a.get("timestamp")]
        return min(timestamps) if timestamps else None

    def _get_last_seen(self, alerts: List[Dict]) -> Optional[str]:
        """Get last seen timestamp from alerts."""
        if not alerts:
            return None
        timestamps = [a.get("timestamp") for a in alerts if a.get("timestamp")]
        return max(timestamps) if timestamps else None
