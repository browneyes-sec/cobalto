"""
STIX2 object mapping for threat intelligence.
Converts internal data structures to STIX2 format.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import uuid
import json


class STIXObjectType(str, Enum):
    INDICATOR = "indicator"
    THREAT_ACTOR = "threat-actor"
    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    INTRUSION_SET = "intrusion-set"
    MALWARE = "malware"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"
    OBSERVABLE = "artifact"
    RELATIONSHIP = "relationship"
    REPORT = "report"
    IDENTITY = "identity"
    LOCATION = "location"


class STIXObject(BaseModel):
    """Base STIX2 object."""
    type: STIXObjectType
    spec_version: str = "2.1"
    id: str = ""
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: datetime = Field(default_factory=datetime.utcnow)
    name: str = ""
    description: str = ""
    labels: List[str] = []
    confidence: int = 0
    lang: str = "en"
    created_by_ref: Optional[str] = None
    object_marking_refs: List[str] = []
    external_references: List[Dict[str, Any]] = []

    def __init__(self, **data):
        super().__init__(**data)
        if not self.id:
            self.id = f"{self.type.value}--{uuid.uuid4()}"


class STIXIndicator(STIXObject):
    """STIX2 Indicator object."""
    type: STIXObjectType = STIXObjectType.INDICATOR
    pattern: str = ""
    pattern_type: str = "stix"
    valid_from: datetime = Field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = None
    indicator_types: List[str] = []
    kill_chain_phases: List[Dict[str, Any]] = []


class STIXThreatActor(STIXObject):
    """STIX2 Threat Actor object."""
    type: STIXObjectType = STIXObjectType.THREAT_ACTOR
    threat_actor_types: List[str] = []
    aliases: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    roles: List[str] = []
    goals: List[str] = []
    sophistication: str = ""
    resource_level: str = ""
    primary_motivation: str = ""
    secondary_motivations: List[str] = []


class STIXAttackPattern(STIXObject):
    """STIX2 Attack Pattern object."""
    type: STIXObjectType = STIXObjectType.ATTACK_PATTERN
    x_mitre_id: str = ""
    x_mitre_detection: str = ""
    x_mitre_platforms: List[str] = []
    x_mitre_data_sources: List[str] = []
    kill_chain_phases: List[Dict[str, Any]] = []


class STIXRelationship(BaseModel):
    """STIX2 Relationship object."""
    type: str = "relationship"
    spec_version: str = "2.1"
    id: str = ""
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: datetime = Field(default_factory=datetime.utcnow)
    relationship_type: str = ""
    source_ref: str = ""
    target_ref: str = ""
    description: str = ""
    start_time: Optional[datetime] = None
    stop_time: Optional[datetime] = None
    confidence: int = 0

    def __init__(self, **data):
        super().__init__(**data)
        if not self.id:
            self.id = f"relationship--{uuid.uuid4()}"


class STIX2Mapper:
    """Maps internal data structures to STIX2 objects."""

    def __init__(self, organization_name: str = "Cobalto"):
        self.organization_name = organization_name
        self._identity_id = f"identity--{uuid.uuid4()}"

    def alert_to_indicator(
        self,
        alert_data: Dict[str, Any],
        confidence: int = 50,
    ) -> STIXIndicator:
        """Convert an alert to a STIX2 Indicator."""
        # Build pattern based on observable type
        pattern = self._build_pattern(alert_data)

        # Extract kill chain phases from MITRE mapping
        kill_chain = []
        for technique in alert_data.get("mitre_techniques", []):
            kill_chain.append({
                "kill_chain_name": "mitre-attack",
                "phase_name": technique.get("tactic", "unknown"),
            })

        return STIXIndicator(
            name=f"Indicator from alert {alert_data.get('id', 'unknown')}",
            description=alert_data.get("description", ""),
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.utcnow(),
            confidence=confidence,
            labels=alert_data.get("tags", []),
            kill_chain_phases=kill_chain,
            created_by_ref=self._identity_id,
        )

    def ip_to_indicator(
        self,
        ip_address: str,
        indicator_type: str = "malicious-activity",
        confidence: int = 70,
    ) -> STIXIndicator:
        """Convert an IP address to a STIX2 Indicator."""
        pattern = f"[ipv4-addr:value = '{ip_address}']"
        return STIXIndicator(
            name=f"IP: {ip_address}",
            description=f"Malicious IP address: {ip_address}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.utcnow(),
            confidence=confidence,
            indicator_types=[indicator_type],
            labels=["malicious-activity"],
        )

    def domain_to_indicator(
        self,
        domain: str,
        indicator_type: str = "malicious-activity",
        confidence: int = 70,
    ) -> STIXIndicator:
        """Convert a domain to a STIX2 Indicator."""
        pattern = f"[domain-name:value = '{domain}']"
        return STIXIndicator(
            name=f"Domain: {domain}",
            description=f"Malicious domain: {domain}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.utcnow(),
            confidence=confidence,
            indicator_types=[indicator_type],
            labels=["malicious-activity"],
        )

    def hash_to_indicator(
        self,
        hash_value: str,
        hash_type: str = "SHA-256",
        indicator_type: str = "malicious-activity",
        confidence: int = 80,
    ) -> STIXIndicator:
        """Convert a file hash to a STIX2 Indicator."""
        hash_map = {
            "MD5": "file:hashes.MD5",
            "SHA-1": "file:hashes.'SHA-1'",
            "SHA-256": "file:hashes.'SHA-256'",
        }
        stix_hash = hash_map.get(hash_type, "file:hashes.'SHA-256'")
        pattern = f"[{stix_hash} = '{hash_value}']"

        return STIXIndicator(
            name=f"File Hash: {hash_value[:16]}...",
            description=f"Malicious file hash ({hash_type}): {hash_value}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.utcnow(),
            confidence=confidence,
            indicator_types=[indicator_type],
            labels=["malicious-activity"],
        )

    def url_to_indicator(
        self,
        url: str,
        indicator_type: str = "malicious-activity",
        confidence: int = 70,
    ) -> STIXIndicator:
        """Convert a URL to a STIX2 Indicator."""
        pattern = f"[url:value = '{url}']"
        return STIXIndicator(
            name=f"URL: {url[:50]}...",
            description=f"Malicious URL: {url}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.utcnow(),
            confidence=confidence,
            indicator_types=[indicator_type],
            labels=["malicious-activity"],
        )

    def email_to_indicator(
        self,
        email: str,
        indicator_type: str = "malicious-activity",
        confidence: int = 70,
    ) -> STIXIndicator:
        """Convert an email to a STIX2 Indicator."""
        pattern = f"[email-addr:value = '{email}']"
        return STIXIndicator(
            name=f"Email: {email}",
            description=f"Malicious email address: {email}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.utcnow(),
            confidence=confidence,
            indicator_types=[indicator_type],
            labels=["malicious-activity"],
        )

    def threat_actor_to_stix(
        self,
        actor_data: Dict[str, Any],
    ) -> STIXThreatActor:
        """Convert threat actor data to STIX2."""
        return STIXThreatActor(
            name=actor_data.get("name", "Unknown"),
            description=actor_data.get("description", ""),
            aliases=actor_data.get("aliases", []),
            threat_actor_types=["crime-syndicate", "nation-state"],
            first_seen=actor_data.get("first_seen"),
            last_seen=actor_data.get("last_seen"),
            roles=actor_data.get("roles", []),
            goals=actor_data.get("goals", []),
            sophistication=actor_data.get("sophistication", "intermediate"),
            resource_level=actor_data.get("resource_level", "organization"),
            primary_motivation=actor_data.get("primary_motivation", "personal-gain"),
            labels=actor_data.get("tags", []),
            created_by_ref=self._identity_id,
        )

    def technique_to_stix(
        self,
        technique_data: Dict[str, Any],
    ) -> STIXAttackPattern:
        """Convert MITRE technique to STIX2 Attack Pattern."""
        return STIXAttackPattern(
            name=technique_data.get("name", "Unknown"),
            description=technique_data.get("description", ""),
            x_mitre_id=technique_data.get("technique_id", ""),
            x_mitre_detection=technique_data.get("detection", ""),
            x_mitre_platforms=technique_data.get("platforms", []),
            x_mitre_data_sources=technique_data.get("data_sources", []),
            kill_chain_phases=technique_data.get("kill_chain_phases", []),
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": technique_data.get("technique_id", ""),
                "url": f"https://attack.mitre.org/techniques/{technique_data.get('technique_id', '')}/",
            }],
        )

    def create_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        description: str = "",
        confidence: int = 50,
    ) -> STIXRelationship:
        """Create a STIX2 Relationship."""
        return STIXRelationship(
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            description=description,
            confidence=confidence,
        )

    def _build_pattern(self, alert_data: Dict[str, Any]) -> str:
        """Build a STIX pattern from alert data."""
        parts = []

        if alert_data.get("source_ip"):
            parts.append(f"[ipv4-addr:value = '{alert_data['source_ip']}']")
        if alert_data.get("destination_ip"):
            parts.append(f"[ipv4-addr:value = '{alert_data['destination_ip']}']")
        if alert_data.get("domain"):
            parts.append(f"[domain-name:value = '{alert_data['domain']}']")
        if alert_data.get("file_hash"):
            parts.append(f"[file:hashes.'SHA-256' = '{alert_data['file_hash']}']")
        if alert_data.get("url"):
            parts.append(f"[url:value = '{alert_data['url']}']")

        if not parts:
            return "[artifact:payload_bin = 'unknown']"

        if len(parts) == 1:
            return parts[0]

        return f"{' AND '.join(parts)}"

    def to_stix_bundle(self, objects: List[STIXObject]) -> Dict[str, Any]:
        """Convert a list of STIX objects to a STIX bundle."""
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [obj.model_dump() for obj in objects],
        }

    def export_stix_json(self, objects: List[STIXObject]) -> str:
        """Export STIX objects as JSON."""
        bundle = self.to_stix_bundle(objects)
        return json.dumps(bundle, indent=2, default=str)