import hashlib
import hmac
import json
import time
import uuid
from typing import Any


class AuditLogger:
    def __init__(self, secret_key: str, log_level: str = "INFO"):
        self._secret_key = secret_key.encode("utf-8")
        self._log_level = log_level
        self._entries: list[dict] = []

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def log_action(
        self,
        agent_id: str,
        action: str,
        details: dict[str, Any] | None = None,
        severity: str = "INFO",
    ) -> dict:
        entry = {
            "timestamp": time.time(),
            "event_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "action": action,
            "details": details or {},
            "severity": severity,
        }
        payload_str = json.dumps(entry, sort_keys=True, default=str)
        entry["hmac_signature"] = self._sign(payload_str)
        self._entries.append(entry)
        print(json.dumps(entry, default=str))
        return entry

    def log_alert_received(self, alert_id: str, alert_data: dict) -> dict:
        return self.log_action(
            agent_id="system",
            action="alert_received",
            details={"alert_id": alert_id, "alert_data": alert_data},
            severity="INFO",
        )

    def log_agent_start(self, agent_id: str, alert_id: str) -> dict:
        return self.log_action(
            agent_id=agent_id,
            action="agent_started",
            details={"alert_id": alert_id},
            severity="INFO",
        )

    def log_agent_complete(self, agent_id: str, alert_id: str, result: dict) -> dict:
        return self.log_action(
            agent_id=agent_id,
            action="agent_completed",
            details={"alert_id": alert_id, "result_summary": str(result)[:500]},
            severity="INFO",
        )

    def log_tool_call(self, agent_id: str, tool_name: str, args: dict, result: Any) -> dict:
        return self.log_action(
            agent_id=agent_id,
            action="tool_called",
            details={
                "tool_name": tool_name,
                "args": args,
                "result_preview": str(result)[:300],
            },
            severity="INFO",
        )

    def log_error(self, agent_id: str, error: str, context: dict | None = None) -> dict:
        return self.log_action(
            agent_id=agent_id,
            action="error",
            details={"error": error, "context": context or {}},
            severity="ERROR",
        )

    def verify_signature(self, entry: dict) -> bool:
        stored_sig = entry.pop("hmac_signature", None)
        if not stored_sig:
            return False
        payload_str = json.dumps(entry, sort_keys=True, default=str)
        expected = self._sign(payload_str)
        return hmac.compare_digest(stored_sig, expected)

    def get_entries(self) -> list[dict]:
        return list(self._entries)
