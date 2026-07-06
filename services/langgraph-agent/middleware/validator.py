from typing import Any

from jsonschema import ValidationError, validate

# Wazuh alert format schema — matches AlertPayload TypedDict from state module
# Used by InputValidator to validate incoming alerts before agent processing
ALERT_PAYLOAD_SCHEMA = {
    "type": "object",
    "required": ["alert_id", "rule_id", "rule_description", "alert_level", "agent_name", "timestamp"],
    "properties": {
        "alert_id": {"type": "string", "minLength": 1},
        "rule_id": {"type": "integer", "minimum": 100000, "maximum": 999999},
        "rule_description": {"type": "string", "minLength": 1},
        "alert_level": {"type": "integer", "minimum": 1, "maximum": 16},
        "source_ip": {"type": "string", "format": "ipv4", "anyOf": [{"type": "string"}, {"type": "null"}]},
        "dest_ip": {"type": "string", "format": "ipv4", "anyOf": [{"type": "string"}, {"type": "null"}]},
        "agent_name": {"type": "string", "minLength": 1},
        "timestamp": {"type": "string"},
        "raw_log": {"type": "string"},
    },
    "additionalProperties": False,
}


class InputValidator:
    def __init__(self, schema: dict[str, Any] | None = None):
        self._schema = schema or ALERT_PAYLOAD_SCHEMA

    def validate(self, payload: dict[str, Any]) -> tuple[bool, str | None]:
        try:
            validate(instance=payload, schema=self._schema)
            return True, None
        except ValidationError as e:
            return False, f"Validation error: {e.message}"

    def reject_malformed(self, payload: dict[str, Any]) -> bool:
        valid, error = self.validate(payload)
        if not valid:
            raise ValueError(error)
        return True

    def validate_severity(self, severity: str) -> bool:
        valid_severities = {"critical", "high", "medium", "low", "info"}
        return severity.lower() in valid_severities

    def validate_indicators(self, indicators: list[dict]) -> list[str]:
        errors = []
        for i, indicator in enumerate(indicators):
            if "type" not in indicator:
                errors.append(f"Indicator {i}: missing 'type' field")
            if "value" not in indicator:
                errors.append(f"Indicator {i}: missing 'value' field")
            if indicator.get("type") in ("ip", "domain", "url", "hash") and not indicator.get("value"):
                errors.append(f"Indicator {i}: empty value for {indicator.get('type')}")
        return errors
