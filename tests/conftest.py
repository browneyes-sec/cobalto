import pytest


@pytest.fixture
def sample_alert_payload():
    return {
        "alert_id": "ALT-2026-001",
        "title": "Brute Force Attack Detected",
        "severity": "high",
        "source": "EDR-SentinelOne",
        "timestamp": "2026-06-25T10:30:00Z",
        "description": "Multiple failed login attempts detected from external IP 203.0.113.42 targeting workstation WS-PROD-17. Over 500 failed attempts within 5 minutes.",
        "indicators": [
            {"type": "ip", "value": "203.0.113.42"},
            {"type": "hostname", "value": "WS-PROD-17"},
            {"type": "user", "value": "admin"},
        ],
        "affected_assets": ["WS-PROD-17", "DC-PRIMARY"],
        "metadata": {
            "src_port": 54321,
            "dst_port": 3389,
            "protocol": "tcp",
            "failed_attempts": 547,
        },
    }


@pytest.fixture
def sample_alert_payload_low():
    return {
        "alert_id": "ALT-2026-002",
        "title": "Scheduled Task Created",
        "severity": "info",
        "source": "SIEM-Splunk",
        "timestamp": "2026-06-25T11:00:00Z",
        "description": "A scheduled task was created on server APP-SRV-03 by SYSTEM account for routine maintenance.",
        "indicators": [
            {"type": "hostname", "value": "APP-SRV-03"},
        ],
        "affected_assets": ["APP-SRV-03"],
        "metadata": {
            "task_name": "WindowsUpdateMaintenance",
            "created_by": "SYSTEM",
        },
    }


@pytest.fixture
def sample_false_positive_alert():
    return {
        "alert_id": "ALT-2026-003",
        "title": "Port Scan Detected - Test",
        "severity": "medium",
        "source": "IDS-Snort",
        "timestamp": "2026-06-25T12:00:00Z",
        "description": "Port scan detected from internal IP 10.0.1.50. NOTE: This is a scheduled vulnerability scan from the security team.",
        "indicators": [
            {"type": "ip", "value": "10.0.1.50"},
        ],
        "affected_assets": ["SCAN-SERVER-01"],
        "metadata": {
            "scan_type": "vulnerability_assessment",
            "authorized": True,
            "scan_window": "maintenance",
        },
    }


@pytest.fixture
def mock_qdrant_client(mocker):
    mock_client = mocker.MagicMock()
    mock_client.search.return_value = [
        mocker.MagicMock(
            id="doc-1",
            payload={
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts.",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            },
            score=0.92,
        ),
        mocker.MagicMock(
            id="doc-2",
            payload={
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "Initial Access",
                "description": "Adversaries may obtain and abuse credentials of existing accounts.",
                "mitre_url": "https://attack.mitre.org/techniques/T1078/",
            },
            score=0.85,
        ),
    ]
    mock_client.get_collections.return_value = ["mitre_attack"]
    return mock_client


@pytest.fixture
def mock_cortex_client(mocker):
    mock_client = mocker.MagicMock()
    mock_analyzer = mocker.MagicMock()
    mock_analyzer.analyze.return_value = {
        "id": "report-001",
        "status": "Success",
        "report": {
            "summary": "IP 203.0.113.42 is a known malicious IP associated with brute force campaigns.",
            "threat_level": "high",
            "tags": ["brute-force", "known-malicious"],
            "ioc_type": "ip",
            "malware_families": ["credential-harvesting"],
        },
    }
    mock_client.analyze_observable.return_value = mock_analyzer.analyze.return_value
    return mock_client


@pytest.fixture
def mock_opencti_client(mocker):
    mock_client = mocker.MagicMock()
    mock_client.query.return_value = {
        "data": {
            "stixDomainObjects": {
                "edges": [
                    {
                        "node": {
                            "id": "indicator-1",
                            "name": "APT29",
                            "description": "Russian state-sponsored threat actor known for sophisticated cyber operations.",
                            "aliases": ["Cozy Bear", "The Dukes"],
                            "primary_motivation": "espionage",
                            "sophistication": "advanced",
                        }
                    }
                ]
            }
        }
    }
    return mock_client
