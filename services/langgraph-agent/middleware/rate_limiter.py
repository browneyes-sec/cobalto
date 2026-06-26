import time
import threading
from dataclasses import dataclass, field


@dataclass
class TokenBucket:
    capacity: float
    tokens: float
    refill_rate: float
    last_refill: float = field(default_factory=time.monotonic)

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class RateLimiter:
    def __init__(self, requests_per_minute: int = 60, token_budget: float | None = None):
        self._requests_per_minute = requests_per_minute
        self._token_budget = token_budget or requests_per_minute * 4.0
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, agent_id: str) -> TokenBucket:
        if agent_id not in self._buckets:
            refill_rate = self._requests_per_minute / 60.0
            self._buckets[agent_id] = TokenBucket(
                capacity=self._requests_per_minute,
                tokens=self._requests_per_minute,
                refill_rate=refill_rate,
            )
        return self._buckets[agent_id]

    def allow(self, agent_id: str, tokens: float = 1.0) -> bool:
        with self._lock:
            bucket = self._get_bucket(agent_id)
            return bucket.consume(tokens)

    def reset(self, agent_id: str | None = None) -> None:
        with self._lock:
            if agent_id:
                self._buckets.pop(agent_id, None)
            else:
                self._buckets.clear()

    def get_usage(self, agent_id: str) -> dict:
        with self._lock:
            bucket = self._get_bucket(agent_id)
            return {
                "agent_id": agent_id,
                "available_tokens": bucket.tokens,
                "capacity": bucket.capacity,
                "requests_per_minute": self._requests_per_minute,
            }
