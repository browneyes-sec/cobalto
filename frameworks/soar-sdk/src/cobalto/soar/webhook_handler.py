"""
Webhook handler for ingesting alerts from various sources.
Validates, normalizes, and routes incoming alerts.
"""

from typing import Any, Dict, List, Optional, Callable, Awaitable
from pydantic import BaseModel, Field, validator
from datetime import datetime
from enum import Enum
from fastapi import APIRouter, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import hashlib
import hmac
import json
from ..core.logging import get_logger
from ..core.metrics import record_alert_processed

logger = get_logger(__name__)


class AlertSource(str, Enum):
    WAZUH = "wazuh"
    OPENCTI = "opencti"
    THEHIVE = "thehive"
    CORTEX = "cortex"
    CLOUDTRAIL = "cloudtrail"
    GUARDDUTY = "guardduty"
    SURICATA = "suricata"
    CUSTOM = "custom"


class WebhookPayload(BaseModel):
    """Standardized webhook payload."""
    source: AlertSource
    event_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_payload: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    signature: Optional[str] = None

    @validator("source", pre=True)
    def validate_source(cls, v):
        if isinstance(v, str):
            return AlertSource(v.lower())
        return v


class NormalizedAlert(BaseModel):
    """Normalized alert format after parsing."""
    alert_id: str
    source: AlertSource
    event_type: str
    severity: str = "informational"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    raw_log: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = {}
    indicators: List[Dict[str, Any]] = []


class WebhookHandler:
    """Handler for webhook alerts."""

    def __init__(self, webhook_secret: Optional[str] = None):
        self.webhook_secret = webhook_secret
        self._parsers: Dict[AlertSource, Callable] = {}
        self._validators: Dict[AlertSource, Callable] = {}
        self._preprocessors: List[Callable] = []
        self._postprocessors: List[Callable] = []
        self.router = APIRouter()
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Setup webhook routes."""
        self.router.add_api_route("/webhook/{source}", self.handle_webhook, methods=["POST"])
        self.router.add_api_route("/webhook", self.handle_webhook_generic, methods=["POST"])

    def register_parser(
        self,
        source: AlertSource,
        parser: Callable[[Dict[str, Any]], NormalizedAlert],
    ) -> None:
        """Register a parser for a specific source."""
        self._parsers[source] = parser
        logger.info("parser_registered", source=source.value)

    def register_validator(
        self,
        source: AlertSource,
        validator: Callable[[Dict[str, Any]], bool],
    ) -> None:
        """Register a validator for a specific source."""
        self._validators[source] = validator

    def add_preprocessor(self, processor: Callable) -> None:
        """Add a preprocessor function."""
        self._preprocessors.append(processor)

    def add_postprocessor(self, processor: Callable) -> None:
        """Add a postprocessor function."""
        self._postprocessors.append(processor)

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify webhook signature."""
        if not self.webhook_secret:
            return True

        expected = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    async def handle_webhook(self, source: str, request: Request) -> JSONResponse:
        """Handle incoming webhook from a specific source."""
        try:
            # Get source
            alert_source = AlertSource(source.lower())

            # Read payload
            body = await request.body()

            # Verify signature if present
            signature = request.headers.get("X-Hub-Signature-256")
            if signature and not self.verify_signature(body, signature):
                logger.warning("webhook_signature_invalid", source=source)
                raise HTTPException(status_code=401, detail="Invalid signature")

            # Parse payload
            payload = json.loads(body)

            # Run preprocessors
            for preprocessor in self._preprocessors:
                payload = await preprocessor(payload)

            # Validate if validator exists
            if alert_source in self._validators:
                if not self._validators[alert_source](payload):
                    logger.warning("webhook_validation_failed", source=source)
                    raise HTTPException(status_code=400, detail="Validation failed")

            # Parse alert
            if alert_source in self._parsers:
                normalized = self._parsers[alert_source](payload)
            else:
                normalized = self._default_parser(alert_source, payload)

            # Run postprocessors
            for postprocessor in self._postprocessors:
                normalized = await postprocessor(normalized)

            # Record metrics
            record_alert_processed(
                "webhook_handler",
                source.value,
                normalized.severity,
                "received",
                0.0,
            )

            logger.info(
                "webhook_received",
                source=source,
                alert_id=normalized.alert_id,
                severity=normalized.severity,
            )

            return JSONResponse(
                status_code=200,
                content={
                    "status": "success",
                    "alert_id": normalized.alert_id,
                    "message": "Alert received and processed",
                },
            )

        except json.JSONDecodeError:
            logger.error("webhook_json_error", source=source)
            raise HTTPException(status_code=400, detail="Invalid JSON")
        except Exception as e:
            logger.exception("webhook_error", source=source, error=str(e))
            raise HTTPException(status_code=500, detail=str(e))

    async def handle_webhook_generic(self, request: Request) -> JSONResponse:
        """Handle generic webhook without source specification."""
        try:
            body = await request.body()
            payload = json.loads(body)

            # Determine source from payload
            source = payload.get("source", "custom")
            try:
                alert_source = AlertSource(source.lower())
            except ValueError:
                alert_source = AlertSource.CUSTOM

            # Use the specific handler
            return await self.handle_webhook(alert_source.value, request)

        except Exception as e:
            logger.exception("generic_webhook_error", error=str(e))
            raise HTTPException(status_code=500, detail=str(e))

    def _default_parser(self, source: AlertSource, payload: Dict[str, Any]) -> NormalizedAlert:
        """Default parser for unknown sources."""
        return NormalizedAlert(
            alert_id=payload.get("id", f"alert-{datetime.utcnow().timestamp()}"),
            source=source,
            event_type=payload.get("event_type", "unknown"),
            severity=payload.get("severity", "informational"),
            source_ip=payload.get("source_ip"),
            destination_ip=payload.get("destination_ip"),
            source_port=payload.get("source_port"),
            destination_port=payload.get("destination_port"),
            protocol=payload.get("protocol"),
            user_name=payload.get("user_name"),
            host_name=payload.get("host_name"),
            rule_id=payload.get("rule_id"),
            rule_description=payload.get("rule_description"),
            raw_log=json.dumps(payload),
            timestamp=datetime.utcnow(),
            metadata=payload.get("metadata", {}),
            indicators=payload.get("indicators", []),
        )

    def create_wazuh_parser(self) -> Callable:
        """Create a parser for Wazuh alerts."""
        def parse_wazuh(payload: Dict[str, Any]) -> NormalizedAlert:
            data = payload.get("data", {})
            return NormalizedAlert(
                alert_id=f"wazuh-{data.get('id', datetime.utcnow().timestamp())}",
                source=AlertSource.WAZUH,
                event_type=data.get("event_type", "alert"),
                severity=self._map_wazuh_severity(data.get("rule", {}).get("level", 0)),
                source_ip=data.get("srcip"),
                destination_ip=data.get("dstip"),
                source_port=data.get("srcport"),
                destination_port=data.get("dstport"),
                protocol=data.get("protocol"),
                user_name=data.get("user"),
                host_name=data.get("hostname"),
                rule_id=str(data.get("rule", {}).get("id", "")),
                rule_description=data.get("rule", {}).get("description", ""),
                raw_log=json.dumps(payload),
                timestamp=datetime.utcnow(),
                metadata={
                    "wazuh_rule_level": data.get("rule", {}).get("level"),
                    "wazuh_agent_id": data.get("agent", {}).get("id"),
                },
                indicators=self._extract_indicators(data),
            )
        return parse_wazuh

    def _map_wazuh_severity(self, level: int) -> str:
        """Map Wazuh rule level to severity."""
        if level >= 12:
            return "critical"
        elif level >= 8:
            return "high"
        elif level >= 4:
            return "medium"
        elif level >= 1:
            return "low"
        return "informational"

    def _extract_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators from alert data."""
        indicators = []

        # IP addresses
        for field in ["srcip", "dstip"]:
            if data.get(field):
                indicators.append({
                    "type": "ip",
                    "value": data[field],
                    "field": field,
                })

        # Domain names
        for field in ["domain"]:
            if data.get(field):
                indicators.append({
                    "type": "domain",
                    "value": data[field],
                    "field": field,
                })

        # File hashes
        for field in ["md5", "sha1", "sha256"]:
            if data.get(field):
                indicators.append({
                    "type": "hash",
                    "hash_type": field,
                    "value": data[field],
                    "field": field,
                })

        # Usernames
        if data.get("user"):
            indicators.append({
                "type": "user",
                "value": data["user"],
                "field": "user",
            })

        return indicators