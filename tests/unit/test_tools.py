import pytest
from unittest.mock import MagicMock, patch


class MockQdrantTool:
    def __init__(self, client):
        self._client = client

    def search_mitre_techniques(self, query: str, limit: int = 5) -> list[dict]:
        results = self._client.search(
            collection_name="mitre_attack",
            query_vector=self._embed(query),
            limit=limit,
        )
        return [
            {"id": r.id, "payload": r.payload, "score": r.score}
            for r in results
        ]

    def _embed(self, text: str) -> list[float]:
        return [0.1] * 384


class MockCortexTool:
    def __init__(self, client):
        self._client = client

    def enrich_ioc(self, ioc_type: str, value: str) -> dict:
        observable = {"dataType": ioc_type, "data": value}
        result = self._client.analyze_observable(
            observable=observable,
            analyzer=["AbuseIPDB", "MaxMind_GeoIP"],
        )
        return result.get("report", {})


class MockOpenCTITool:
    def __init__(self, client):
        self._client = client

    def query_actors(self, search: str) -> list[dict]:
        query = """
        query StixDomainObjects($search: String) {
            stixDomainObjects(search: $search, types: ["Threat-Actor"]) {
                edges {
                    node {
                        id
                        name
                        description
                        ... on ThreatActor {
                            aliases
                            primary_motivation
                            sophistication
                        }
                    }
                }
            }
        }
        """
        result = self._client.query(query, variables={"search": search})
        edges = result.get("data", {}).get("stixDomainObjects", {}).get("edges", [])
        return [e["node"] for e in edges]


class TestMitreAttackSearch:
    def test_mitre_attack_search_returns_results(self, mock_qdrant_client):
        tool = MockQdrantTool(mock_qdrant_client)
        results = tool.search_mitre_techniques("brute force attack pattern")
        assert len(results) > 0
        assert results[0]["score"] > 0.8
        assert "T1110" in results[0]["payload"]["technique_id"]
        mock_qdrant_client.search.assert_called_once()

    def test_mitre_attack_search_specific_technique(self, mock_qdrant_client):
        tool = MockQdrantTool(mock_qdrant_client)
        results = tool.search_mitre_techniques("credential access")
        assert len(results) > 0
        assert all("technique_id" in r["payload"] for r in results)


class TestEnrichIoc:
    def test_enrich_ioc_returns_report(self, mock_cortex_client):
        tool = MockCortexTool(mock_cortex_client)
        report = tool.enrich_ioc("ip", "203.0.113.42")
        assert "summary" in report
        assert "threat_level" in report
        assert report["threat_level"] == "high"
        mock_cortex_client.analyze_observable.assert_called_once()

    def test_enrich_ioc_multiple_observables(self, mock_cortex_client):
        tool = MockCortexTool(mock_cortex_client)
        report = tool.enrich_ioc("domain", "malicious-domain.example.com")
        assert "tags" in report
        assert isinstance(report["tags"], list)


class TestOpenCTIQuery:
    def test_opencti_query_returns_actors(self, mock_opencti_client):
        tool = MockOpenCTITool(mock_opencti_client)
        actors = tool.query_actors("APT29")
        assert len(actors) > 0
        assert actors[0]["name"] == "APT29"
        assert "Cozy Bear" in actors[0]["aliases"]
        mock_opencti_client.query.assert_called_once()

    def test_opencti_query_returns_motivation(self, mock_opencti_client):
        tool = MockOpenCTITool(mock_opencti_client)
        actors = tool.query_actors("APT29")
        assert actors[0]["primary_motivation"] == "espionage"
        assert actors[0]["sophistication"] == "advanced"

    def test_opencti_query_empty_results(self, mock_opencti_client):
        mock_opencti_client.query.return_value = {
            "data": {"stixDomainObjects": {"edges": []}}
        }
        tool = MockOpenCTITool(mock_opencti_client)
        actors = tool.query_actors("nonexistent_actor_xyz")
        assert len(actors) == 0
