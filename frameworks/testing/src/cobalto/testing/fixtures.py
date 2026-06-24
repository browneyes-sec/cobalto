"""
Test fixtures for Cobalto.
Provides sample data for testing.
"""

from typing import Any, Dict, List
from datetime import datetime, timedelta
import random
import string


def random_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def random_hash(length: int = 64) -> str:
    """Generate a random hash."""
    return "".join(random.choices(string.hexdigits[:16], k=length))


def random_domain() -> str:
    """Generate a random domain."""
    words = ["malware", "c2", "phishing", "exploit", "bot", "spam", "attack"]
    tlds = [".com", ".net", ".org", ".ru", ".cn"]
    return f"{random.choice(words)}{''.join(random.choices(string.ascii_lowercase, k=8))}{random.choice(tlds)}"


# Alert fixtures
def alert_fixtures() -> List[Dict[str, Any]]:
    """Generate sample alert fixtures."""
    return [
        {
            "id": "alert-001",
            "source": "wazuh",
            "event_type": "alert",
            "severity": "high",
            "source_ip": "203.0.113.45",
            "destination_ip": "192.168.1.100",
            "source_port": 4444,
            "destination_port": 22,
            "protocol": "tcp",
            "user_name": "admin",
            "host_name": "webserver-01",
            "rule_id": "5712",
            "rule_description": "Possible brute force attack detected",
            "raw_log": '{"action": "SSH brute force attempt", "count": 15}',
            "timestamp": datetime.utcnow().isoformat(),
            "tags": ["brute-force", "ssh", "high-severity"],
            "indicators": [
                {"type": "ip", "value": "203.0.113.45"},
                {"type": "user", "value": "admin"},
            ],
        },
        {
            "id": "alert-002",
            "source": "wazuh",
            "event_type": "alert",
            "severity": "critical",
            "source_ip": "198.51.100.23",
            "destination_ip": "10.0.0.50",
            "source_port": 8080,
            "destination_port": 445,
            "protocol": "tcp",
            "user_name": None,
            "host_name": "fileserver-01",
            "rule_id": "10001",
            "rule_description": "Ransomware behavior detected - mass file encryption",
            "raw_log": '{"action": "File encryption detected", "files": 150}',
            "timestamp": datetime.utcnow().isoformat(),
            "tags": ["ransomware", "encryption", "critical"],
            "indicators": [
                {"type": "ip", "value": "198.51.100.23"},
                {"type": "hash", "hash_type": "sha256", "value": random_hash()},
            ],
        },
        {
            "id": "alert-003",
            "source": "suricata",
            "event_type": "ids",
            "severity": "medium",
            "source_ip": "198.51.100.42",
            "destination_ip": "192.168.1.200",
            "source_port": 12345,
            "destination_port": 80,
            "protocol": "tcp",
            "user_name": None,
            "host_name": "webserver-02",
            "rule_id": "2024567",
            "rule_description": "ET MALWARE Trickbot CnC Communication",
            "raw_log": '{"alert": {"signature": "Trickbot CnC"}}',
            "timestamp": datetime.utcnow().isoformat(),
            "tags": ["malware", "c2", "trickbot"],
            "indicators": [
                {"type": "ip", "value": "198.51.100.42"},
                {"type": "domain", "value": random_domain()},
            ],
        },
        {
            "id": "alert-004",
            "source": "cloudtrail",
            "event_type": "cloud",
            "severity": "high",
            "source_ip": "192.0.2.100",
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "user_name": "devops-admin",
            "host_name": "aws-console",
            "rule_id": "CT-001",
            "rule_description": "Root login detected from unusual location",
            "raw_log": '{"event": "ConsoleLogin", "userIdentity": {"type": "Root"}}',
            "timestamp": datetime.utcnow().isoformat(),
            "tags": ["cloud", "iam", "root-login"],
            "indicators": [
                {"type": "ip", "value": "192.0.2.100"},
                {"type": "user", "value": "devops-admin"},
            ],
        },
        {
            "id": "alert-005",
            "source": "wazuh",
            "event_type": "alert",
            "severity": "low",
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "user_name": "testuser",
            "host_name": "workstation-01",
            "rule_id": "18101",
            "rule_description": "User successfully logged in",
            "raw_log": '{"action": "login_success"}',
            "timestamp": datetime.utcnow().isoformat(),
            "tags": ["authentication", "success"],
            "indicators": [
                {"type": "user", "value": "testuser"},
            ],
        },
    ]


# Threat intelligence fixtures
def threat_intel_fixtures() -> List[Dict[str, Any]]:
    """Generate sample threat intelligence fixtures."""
    return [
        {
            "technique_id": "T1110",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to gain access to accounts.",
            "tactics": [
                {"tactic_id": "credential-access", "tactic_name": "Credential Access"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Authentication logs", "VPN logs"],
            "kill_chain_phases": [
                {"chain_name": "mitre-attack", "phase_name": "credential-access"},
            ],
        },
        {
            "technique_id": "T1486",
            "name": "Data Encrypted for Impact",
            "description": "Adversaries may encrypt data on target systems to interrupt availability.",
            "tactics": [
                {"tactic_id": "impact", "tactic_name": "Impact"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["File monitoring", "Process monitoring"],
            "kill_chain_phases": [
                {"chain_name": "mitre-attack", "phase_name": "impact"},
            ],
        },
        {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "tactics": [
                {"tactic_id": "execution", "tactic_name": "Execution"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Process monitoring", "Command-line logging"],
            "kill_chain_phases": [
                {"chain_name": "mitre-attack", "phase_name": "execution"},
            ],
        },
        {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials of existing accounts.",
            "tactics": [
                {"tactic_id": "persistence", "tactic_name": "Persistence"},
                {"tactic_id": "privilege-escalation", "tactic_name": "Privilege Escalation"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Authentication logs", "Process monitoring"],
            "kill_chain_phases": [
                {"chain_name": "mitre-attack", "phase_name": "persistence"},
                {"chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
            ],
        },
        {
            "technique_id": "T1566",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages to gain access to victim systems.",
            "tactics": [
                {"tactic_id": "initial-access", "tactic_name": "Initial Access"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Email gateway logs", "User reports"],
            "kill_chain_phases": [
                {"chain_name": "mitre-attack", "phase_name": "initial-access"},
            ],
        },
    ]


# Case fixtures
def case_fixtures() -> List[Dict[str, Any]]:
    """Generate sample case fixtures."""
    return [
        {
            "caseId": "CASE-2026-001",
            "title": "Brute Force Attack on Web Server",
            "description": "Multiple failed login attempts detected from external IP",
            "severity": 2,
            "status": "Open",
            "tags": ["brute-force", "ssh", "web-server"],
            "metrics": {
                "alertCount": 15,
                "observableCount": 3,
                "taskCount": 5,
            },
            "createdAt": datetime.utcnow().isoformat(),
        },
        {
            "caseId": "CASE-2026-002",
            "title": "Ransomware Incident - File Server",
            "description": "Ransomware encryption detected on file server",
            "severity": 3,
            "status": "In Progress",
            "tags": ["ransomware", "encryption", "critical"],
            "metrics": {
                "alertCount": 25,
                "observableCount": 8,
                "taskCount": 10,
            },
            "createdAt": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
        },
        {
            "caseId": "CASE-2026-003",
            "title": "Phishing Campaign Targeting Finance",
            "description": "Targeted phishing emails sent to finance department",
            "severity": 2,
            "status": "Open",
            "tags": ["phishing", "finance", "targeted"],
            "metrics": {
                "alertCount": 10,
                "observableCount": 5,
                "taskCount": 3,
            },
            "createdAt": (datetime.utcnow() - timedelta(hours=4)).isoformat(),
        },
    ]


# MITRE ATT&CK fixtures
def mitre_fixtures() -> List[Dict[str, Any]]:
    """Generate sample MITRE ATT&CK fixtures."""
    return [
        {
            "technique_id": "T1110.001",
            "name": "Brute Force: Password Guessing",
            "description": "Adversaries may guess passwords without relying on any known passwords.",
            "tactics": [
                {"tactic_id": "credential-access", "tactic_name": "Credential Access"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
        },
        {
            "technique_id": "T1110.002",
            "name": "Brute Force: Password Cracking",
            "description": "Adversaries may crack password hashes.",
            "tactics": [
                {"tactic_id": "credential-access", "tactic_name": "Credential Access"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
        },
        {
            "technique_id": "T1110.003",
            "name": "Brute Force: Password Spraying",
            "description": "Adversaries may use a single password against many accounts.",
            "tactics": [
                {"tactic_id": "credential-access", "tactic_name": "Credential Access"},
            ],
            "platforms": ["Windows", "Linux", "macOS"],
        },
    ]


# IOC fixtures
def ioc_fixtures() -> List[Dict[str, Any]]:
    """Generate sample IOC fixtures."""
    return [
        {"type": "ip", "value": "203.0.113.45", "confidence": 85, "tags": ["malicious"]},
        {"type": "ip", "value": "198.51.100.23", "confidence": 95, "tags": ["malicious", "c2"]},
        {"type": "domain", "value": "evil-c2.example.com", "confidence": 90, "tags": ["c2"]},
        {"type": "hash", "hash_type": "sha256", "value": random_hash(), "confidence": 100, "tags": ["malware"]},
        {"type": "url", "value": "http://malware.example.com/payload.exe", "confidence": 88, "tags": ["malware"]},
    ]


# Agent fixtures
def agent_fixtures() -> List[Dict[str, Any]]:
    """Generate sample agent fixtures."""
    return [
        {
            "agent_id": "triage-001",
            "agent_type": "triage",
            "status": "running",
            "current_task": "alert-001",
            "metrics": {
                "processed": 150,
                "avg_duration": 2.5,
            },
        },
        {
            "agent_id": "analysis-001",
            "agent_type": "analysis",
            "status": "idle",
            "current_task": None,
            "metrics": {
                "processed": 45,
                "avg_duration": 15.2,
            },
        },
        {
            "agent_id": "response-001",
            "agent_type": "response",
            "status": "waiting",
            "current_task": "approval-001",
            "metrics": {
                "processed": 20,
                "avg_duration": 5.0,
            },
        },
    ]