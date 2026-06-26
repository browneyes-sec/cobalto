from typing import Any

from jsonschema import ValidationError, validate

ALERT_PAYLOAD_SCHEMA = {
    "type": "object",
    "required": ["alert_id", "title", "severity", "source", "timestamp"],
    "properties": {
        "alert_id": {"type": "string", "minLength": 1},
        "title": {"type": "string", "minLength": 1},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "source": {"type": "string", "minLength": 1},
        "timestamp": {"type": "string"},
        "description": {"type": "string"},
        "indicators": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "value": {"type": "string"},
                },
            },
        },
        "affected_assets": {"type": "array", "items": {"type": "string"}},
        "metadata": {"type": "object"},
    },
    "additionalProperties": True,
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
