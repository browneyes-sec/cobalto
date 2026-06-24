"""
Unit tests for Intel SDK.
"""

import pytest
from cobalto.intel.stix2_mapper import STIX2Mapper, STIXIndicator, STIXThreatActor, STIXObjectType
from cobalto.intel.mitre import MITREMapper, MITRTechnique, MITRETactic


class TestSTIX2Mapper:
    """Test STIX2 mapper."""

    def test_mapper_creation(self):
        """Test mapper creation."""
        mapper = STIX2Mapper(organization_name="Cobalto")
        assert mapper.organization_name == "Cobalto"

    def test_ip_to_indicator(self):
        """Test IP to STIX indicator conversion."""
        mapper = STIX2Mapper()
        indicator = mapper.ip_to_indicator("203.0.113.45")
        assert isinstance(indicator, STIXIndicator)
        assert indicator.type == STIXObjectType.INDICATOR
        assert "203.0.113.45" in indicator.pattern

    def test_domain_to_indicator(self):
        """Test domain to STIX indicator conversion."""
        mapper = STIX2Mapper()
        indicator = mapper.domain_to_indicator("evil.com")
        assert isinstance(indicator, STIXIndicator)
        assert "evil.com" in indicator.pattern

    def test_hash_to_indicator(self):
        """Test hash to STIX indicator conversion."""
        mapper = STIX2Mapper()
        indicator = mapper.hash_to_indicator("abc123", hash_type="SHA-256")
        assert isinstance(indicator, STIXIndicator)
        assert "abc123" in indicator.pattern

    def test_url_to_indicator(self):
        """Test URL to STIX indicator conversion."""
        mapper = STIX2Mapper()
        indicator = mapper.url_to_indicator("http://evil.com/payload")
        assert isinstance(indicator, STIXIndicator)
        assert "evil.com" in indicator.pattern

    def test_threat_actor_to_stix(self):
        """Test threat actor conversion."""
        mapper = STIX2Mapper()
        actor = mapper.threat_actor_to_stix({
            "name": "APT28",
            "description": "Russian threat actor",
            "aliases": ["Fancy Bear"],
        })
        assert isinstance(actor, STIXThreatActor)
        assert actor.name == "APT28"

    def test_create_relationship(self):
        """Test relationship creation."""
        mapper = STIX2Mapper()
        rel = mapper.create_relationship(
            source_id="indicator--123",
            target_id="threat-actor--456",
            relationship_type="indicates",
        )
        assert rel.relationship_type == "indicates"
        assert rel.source_ref == "indicator--123"

    def test_to_stix_bundle(self):
        """Test STIX bundle creation."""
        mapper = STIX2Mapper()
        indicator = mapper.ip_to_indicator("203.0.113.45")
        bundle = mapper.to_stix_bundle([indicator])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1

    def test_export_stix_json(self):
        """Test STIX JSON export."""
        mapper = STIX2Mapper()
        indicator = mapper.ip_to_indicator("203.0.113.45")
        json_str = mapper.export_stix_json([indicator])
        assert isinstance(json_str, str)
        assert "203.0.113.45" in json_str


class TestMITREMapper:
    """Test MITRE mapper."""

    def test_mapper_creation(self):
        """Test mapper creation."""
        mapper = MITREMapper(qdrant_url="http://localhost:6333")
        assert mapper.qdrant_url == "http://localhost:6333"

    def test_technique_creation(self):
        """Test technique creation."""
        technique = MITRTechnique(
            id="attack-pattern--123",
            technique_id="T1110",
            name="Brute Force",
            description="Brute force technique",
        )
        assert technique.technique_id == "T1110"
        assert technique.name == "Brute Force"

    def test_tactic_creation(self):
        """Test tactic creation."""
        tactic = MITRETactic(
            id="credential-access",
            name="Credential Access",
        )
        assert tactic.id == "credential-access"

    def test_build_search_query(self):
        """Test search query building."""
        mapper = MITREMapper(qdrant_url="http://localhost:6333")
        query = mapper._build_search_query({
            "rule_description": "Brute force attack",
            "source_ip": "203.0.113.45",
        })
        assert "Brute force" in query
        assert "203.0.113.45" in query

    def test_extract_keywords(self):
        """Test keyword extraction."""
        mapper = MITREMapper(qdrant_url="http://localhost:6333")
        keywords = mapper._extract_keywords({
            "rule_description": "Brute force SSH attack",
            "event_type": "authentication",
        })
        assert "Brute" in keywords
        assert "force" in keywords

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        mapper = MITREMapper(qdrant_url="http://localhost:6333")
        techniques = [
            MITRTechnique(
                id="attack-pattern--123",
                technique_id="T1110",
                name="Brute Force",
                detection="Monitor authentication logs",
            )
        ]
        recommendations = mapper._generate_recommendations(techniques)
        assert len(recommendations) > 0

    def test_get_technique_count(self):
        """Test technique count."""
        mapper = MITREMapper(qdrant_url="http://localhost:6333")
        assert mapper.get_technique_count() == 0

    def test_list_tactics(self):
        """Test tactic listing."""
        mapper = MITREMapper(qdrant_url="http://localhost:6333")
        tactics = mapper.list_tactics()
        assert isinstance(tactics, list)