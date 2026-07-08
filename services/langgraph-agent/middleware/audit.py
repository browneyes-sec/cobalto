"""
Structured Audit Logging for Cobalto LangGraph Agent.

Provides HMAC-signed audit entries with structured JSON output.
Integrates with Python's logging framework for flexible log shipping
via Fluent Bit, Logstash, or direct Elasticsearch ingestion.

Features:
  - HMAC-SHA256 signed entries (tamper-evident)
  - Structured JSON output to stderr (container-native)
  - Integration with Python logging framework
  - Standardized event types for SOC workflows
  - Backward-compatible with existing consumers

Usage:
    from middleware.audit import audit_logger

    audit_logger.info("alert_received", alert_id="ALT-001", source="wazuh")
    audit_logger.error("analysis_failed", alert_id="ALT-001", error="timeout")

Configuration:
    HMAC_SECRET: Secret key for HMAC signing (default: "change-me-in-production")
    LOG_LEVEL: Logging level (default: "INFO")
"""

import hashlib
import hmac
import json
import logging
import time
import uuid
import os
from typing import Any


# ── Structured JSON Formatter ───────────────────────────────────────

class AuditJSONFormatter(logging.Formatter):
    """Formats log records as JSON for structured log shipping."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }

        # Include extra fields passed to the logger
        if hasattr(record, "audit_fields") and record.audit_fields:
            log_entry.update(record.audit_fields)

        # Include exception info if present
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }

        return json.dumps(log_entry, default=str, ensure_ascii=False)


def setup_audit_logger(name: str = "cobalto.audit", level: str = "INFO") -> logging.Logger:
    """
    Configure and return a structured JSON logger.

    Writes JSON-formatted log entries to stderr for container-native
    log collection (Fluent Bit, CloudWatch, etc.).
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Only add handler if none exist (avoid duplicate handlers on re-import)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(AuditJSONFormatter())
        logger.addHandler(handler)

    # Prevent propagation to root logger (avoids duplicate output)
    logger.propagate = False

    return logger


# ── Audit Logger (HMAC-Signed) ──────────────────────────────────────

class AuditLogger:
    """
    Tamper-evident audit logger with HMAC-SHA256 signing.

    Every audit entry is signed with an HMAC key, allowing verification
    that the entry has not been tampered with after creation.

    The logger writes structured JSON to stderr via Python's logging
    framework, making it compatible with standard log collection
    pipelines (Fluent Bit, Logstash, CloudWatch, etc.).
    """

    def __init__(self, secret_key: str | None = None, log_level: str | None = None):
        secret = secret_key or os.getenv("HMAC_SECRET", "change-me-in-production")
        level = log_level or os.getenv("LOG_LEVEL", "INFO")

        self._secret_key = secret.encode("utf-8")
        self._logger = setup_audit_logger(level=level)
        self._entries: list[dict] = []

    def _sign(self, payload: str) -> str:
        """Generate HMAC-SHA256 signature for the given payload."""
        return hmac.new(self._secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def _make_entry(
        self,
        agent_id: str,
        action: str,
        details: dict[str, Any] | None = None,
        severity: str = "INFO",
    ) -> dict:
        """Create a signed audit entry."""
        entry = {
            "timestamp": time.time(),
            "event_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "action": action,
            "details": details or {},
            "severity": severity.upper(),
        }
        payload_str = json.dumps(entry, sort_keys=True, default=str)
        entry["hmac_signature"] = self._sign(payload_str)
        return entry

    def _emit(self, entry: dict) -> dict:
        """Emit an audit entry: store in memory, log via structured JSON."""
        self._entries.append(entry)

        # Log through Python logging framework with extra audit fields
        log_level = entry.get("severity", "INFO").lower()
        log_method = getattr(self._logger, log_level, self._logger.info)

        extra = {"audit_fields": entry}
        log_method(
            "Audit: %s | agent=%s | event=%s",
            entry["action"],
            entry["agent_id"],
            entry["event_id"],
            extra=extra,
        )

        return entry

    # ── Public API ─────────────────────────────────────────────────

    def log_action(
        self,
        agent_id: str,
        action: str,
        details: dict[str, Any] | None = None,
        severity: str = "INFO",
    ) -> dict:
        """Log an arbitrary action with HMAC-signed entry."""
        entry = self._make_entry(agent_id, action, details, severity)
        return self._emit(entry)

    def log_alert_received(self, alert_id: str, alert_data: dict) -> dict:
        """Log that an alert was received from an external source."""
        return self.log_action(
            agent_id="system",
            action="alert_received",
            details={"alert_id": alert_id, "alert_data": alert_data},
            severity="INFO",
        )

    def log_agent_start(self, agent_id: str, alert_id: str) -> dict:
        """Log that an agent began processing an alert."""
        return self.log_action(
            agent_id=agent_id,
            action="agent_started",
            details={"alert_id": alert_id},
            severity="INFO",
        )

    def log_agent_complete(self, agent_id: str, alert_id: str, result: dict) -> dict:
        """Log that an agent completed processing."""
        return self.log_action(
            agent_id=agent_id,
            action="agent_completed",
            details={"alert_id": alert_id, "result_summary": str(result)[:500]},
            severity="INFO",
        )

    def log_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        args: dict,
        result: Any,
        status: str = "success",
        duration_ms: float | None = None,
    ) -> dict:
        """Log an external tool invocation and record Prometheus metrics.

        Parameters
        ----------
        status:
            One of ``"success"``, ``"error"``, or ``"unknown"``.
            Determines the Prometheus ``status`` label value.
        duration_ms:
            Tool execution duration in milliseconds. If provided, the
            ``cobalto_tool_latency_seconds`` histogram is updated.
        """
        entry = self.log_action(
            agent_id=agent_id,
            action="tool_called",
            details={
                "tool_name": tool_name,
                "args": args,
                "result_preview": str(result)[:300],
                "status": status,
                "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
            },
            severity="INFO",
        )
        # Record Prometheus metrics in-band with the audit log
        try:
            from middleware.metrics import metrics as _metrics

            _metrics.tool_call(
                tool_name=tool_name,
                duration_seconds=(duration_ms / 1000.0) if duration_ms is not None else 0.0,
                status=status,
            )
        except Exception:
            self.logger.warning(
                "Failed to record Prometheus metrics for tool call",
                extra={"tool_name": tool_name},
            )
        return entry

    def log_error(self, agent_id: str, error: str, context: dict | None = None) -> dict:
        """Log an error with context."""
        return self.log_action(
            agent_id=agent_id,
            action="error",
            details={"error": error, "context": context or {}},
            severity="ERROR",
        )

    # ── PCI DSS 10.2 Audit Events ──────────────────────────────────

    def log_user_access(self, user_id: str, resource: str, action: str = "access") -> dict:
        """Log individual user access to data (PCI DSS 10.2.1)."""
        return self.log_action(
            agent_id=user_id,
            action="user_access",
            details={"resource": resource, "access_type": action},
            severity="INFO",
        )

    def log_admin_action(self, admin_id: str, command: str, target: str) -> dict:
        """Log actions by administrative users (PCI DSS 10.2.2)."""
        return self.log_action(
            agent_id=admin_id,
            action="admin_action",
            details={"command": command, "target": target},
            severity="INFO",
        )

    def log_audit_access(self, user_id: str, audit_resource: str) -> dict:
        """Log access to audit trail (PCI DSS 10.2.3)."""
        return self.log_action(
            agent_id=user_id,
            action="audit_access",
            details={"audit_resource": audit_resource},
            severity="INFO",
        )

    def log_auth_attempt(self, user_id: str, source_ip: str, success: bool) -> dict:
        """Log authentication attempt — success or failure (PCI DSS 10.2.4/10.2.5)."""
        return self.log_action(
            agent_id=user_id,
            action="auth_attempt",
            details={"source_ip": source_ip, "success": success},
            severity="INFO" if success else "WARNING",
        )

    def log_auth_change(self, user_id: str, change_type: str, detail: str) -> dict:
        """Log changes to authentication mechanisms (PCI DSS 10.2.5)."""
        return self.log_action(
            agent_id=user_id,
            action="auth_change",
            details={"change_type": change_type, "detail": detail},
            severity="WARNING",
        )

    def log_config_change(self, agent_id: str, config_key: str, old_value: str, new_value: str) -> dict:
        """Log configuration changes (PCI DSS 10.2.6)."""
        return self.log_action(
            agent_id=agent_id,
            action="config_change",
            details={"key": config_key, "from": old_value, "to": new_value},
            severity="WARNING",
        )

    def log_audit_init(self, reason: str = "service_start") -> dict:
        """Log audit log initialization (PCI DSS 10.2.7)."""
        return self.log_action(
            agent_id="system",
            action="audit_init",
            details={"reason": reason},
            severity="INFO",
        )

    def log_object_create(self, agent_id: str, object_type: str, object_id: str) -> dict:
        """Log creation of system-level objects (PCI DSS 10.2.8)."""
        return self.log_action(
            agent_id=agent_id,
            action="object_create",
            details={"object_type": object_type, "object_id": object_id},
            severity="INFO",
        )

    def log_object_delete(self, agent_id: str, object_type: str, object_id: str) -> dict:
        """Log deletion of system-level objects (PCI DSS 10.2.8)."""
        return self.log_action(
            agent_id=agent_id,
            action="object_delete",
            details={"object_type": object_type, "object_id": object_id},
            severity="WARNING",
        )

    # ── Tamper Verification ────────────────────────────────────────

    def verify_signature(self, entry: dict) -> bool:
        """
        Verify HMAC signature of an audit entry.

        Returns True if the signature matches the entry content,
        False if the entry has been tampered with.
        """
        stored_sig = entry.pop("hmac_signature", None)
        if not stored_sig:
            return False
        payload_str = json.dumps(entry, sort_keys=True, default=str)
        expected = self._sign(payload_str)
        return hmac.compare_digest(stored_sig, expected)

    # ── Data Access ────────────────────────────────────────────────

    def get_entries(self) -> list[dict]:
        """Return all audit entries collected in memory."""
        return list(self._entries)

    def get_entries_by_agent(self, agent_id: str) -> list[dict]:
        """Filter entries by agent ID."""
        return [e for e in self._entries if e["agent_id"] == agent_id]

    def get_entries_by_action(self, action: str) -> list[dict]:
        """Filter entries by action type."""
        return [e for e in self._entries if e["action"] == action]

    def get_entries_by_severity(self, severity: str) -> list[dict]:
        """Filter entries by severity level."""
        return [e for e in self._entries if e["severity"] == severity.upper()]

    def clear(self) -> None:
        """Clear all in-memory entries (memory management)."""
        self._entries.clear()

    @property
    def count(self) -> int:
        """Number of entries collected."""
        return len(self._entries)


# ── Module-Level Convenience ────────────────────────────────────────

# Default instance for simple import
_default_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get or create the default audit logger instance."""
    global _default_logger
    if _default_logger is None:
        _default_logger = AuditLogger()
    return _default_logger


def audit_info(action: str, **details: Any) -> dict:
    """Convenience: log an INFO-level audit event."""
    return get_audit_logger().log_action("system", action, details, "INFO")


def audit_error(action: str, error: str, **context: Any) -> dict:
    """Convenience: log an ERROR-level audit event."""
    return get_audit_logger().log_error("system", error, context or {})
